//! `krb5-operator node-agent`: the `KerberosNodeKeytab` DaemonSet's pod.
//! It installs the node's keys (`<keytabs>/<NODE_NAME>.keytab`, from the
//! Secret) into the host keytab, and the realm's `krb5.conf` if asked, and
//! keeps them current: a Secret update reaches the pod's files, and the
//! agent looks every few seconds.
//!
//! The host keytab is merged, entry by entry and byte for byte: entries of
//! other realms (the node's own, from elsewhere) are kept as they are,
//! whatever their enctype; entries of the operator's realm are replaced by
//! the node's current keys. A file is written only when its bytes change,
//! to a temporary file in the same directory, synced, then renamed over the
//! old one, so rpc.gssd never reads half a keytab. A host keytab that is
//! not a keytab is left alone (and the agent is not ready).
//!
//! With `--restart=<unit>` (the spec's `restartServices`) the agent also
//! has the host's systemd start each unit when it starts, and restart it
//! whenever it writes a file ([`crate::systemd`]). That is for `rpc-gssd`:
//! nfs-utils' unit has `ConditionPathExists=/etc/krb5.keytab`, so on a node
//! that booted before its keys arrived it never ran, and a `try-restart`
//! would leave it so. A unit the host does not have, or has masked, is
//! skipped (logged once); a call that fails is tried again on the next
//! pass, and the agent is not ready until it works.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail};
use tracing::{info, warn};

/// One keytab entry: its realm, and its bytes (without the length).
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub realm: String,
    pub bytes: Vec<u8>,
}

/// The entries of an MIT keytab (version 0x502); deleted entries (negative
/// lengths, holes) are dropped. An empty file has none.
pub fn entries(data: &[u8]) -> anyhow::Result<Vec<Entry>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data.len() < 2 || data[0] != 5 || data[1] != 2 {
        bail!("not a version 0x502 keytab");
    }
    let mut out = Vec::new();
    let mut at = 2;
    while at < data.len() {
        let Some(len) = data.get(at..at + 4) else { bail!("truncated entry length at {at}") };
        let len = i32::from_be_bytes(len.try_into().expect("4 bytes"));
        at += 4;
        let size = len.unsigned_abs() as usize;
        let Some(body) = data.get(at..at + size) else { bail!("truncated entry at {at}") };
        at += size;
        if len <= 0 {
            continue;
        }
        // num_components (2), then the realm: length (2), bytes.
        let realm = body
            .get(2..4)
            .map(|l| u16::from_be_bytes([l[0], l[1]]) as usize)
            .and_then(|n| body.get(4..4 + n))
            .ok_or_else(|| anyhow::anyhow!("entry at {at} too short for its realm"))?;
        out.push(Entry { realm: String::from_utf8_lossy(realm).into_owned(), bytes: body.to_vec() });
    }
    Ok(out)
}

/// `host` (the host keytab's bytes) with the entries of `ours`' realms
/// replaced by `ours`.
pub fn merge(host: &[u8], ours: &[u8]) -> anyhow::Result<Vec<u8>> {
    let ours = entries(ours).context("the node's keys")?;
    let realms: BTreeSet<&str> = ours.iter().map(|e| e.realm.as_str()).collect();
    let kept = entries(host).context("the host keytab")?;
    let mut out = vec![5, 2];
    for e in kept.iter().filter(|e| !realms.contains(e.realm.as_str())).chain(&ours) {
        out.extend((e.bytes.len() as i32).to_be_bytes());
        out.extend(&e.bytes);
    }
    Ok(out)
}

/// Replace `path` with `data` (mode `mode`) unless it already holds it:
/// a temporary file beside it, synced, renamed over it. Whether it wrote.
pub fn write_if_changed(path: &Path, data: &[u8], mode: u32) -> anyhow::Result<bool> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if std::fs::read(path).ok().as_deref() == Some(data) {
        return Ok(false);
    }
    let dir = path.parent().context("no directory")?;
    let name = path.file_name().context("no file name")?.to_string_lossy();
    let tmp = dir.join(format!(".{name}.krb5-operator.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(data)?;
    f.set_permissions(std::fs::Permissions::from_mode(mode))?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path).with_context(|| format!("renaming over {}", path.display()))?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(true)
}

pub struct Options {
    pub keytabs: PathBuf,
    pub node: String,
    pub keytab: PathBuf,
    pub krb5_conf: Option<PathBuf>,
    /// systemd units to start, and restart when a file changes.
    pub restart: Vec<String>,
    /// The host systemd's private socket, as the pod mounts it.
    pub systemd: PathBuf,
}

/// What the agent owes the units of `--restart`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kick {
    /// Start them if they are not running (the agent just started: they
    /// may never have run, or a node rebooted before its keys came).
    Start,
    /// Restart them: a file they read changed.
    Restart,
}

impl Kick {
    fn method(self) -> &'static str {
        match self {
            Kick::Start => "StartUnit",
            Kick::Restart => "RestartUnit",
        }
    }
}

/// What is owed after a pass that changed `changed`, given what was owed:
/// a restart outranks a start, and nothing is owed without units.
pub fn owed(before: Option<Kick>, changed: &[String], units: &[String]) -> Option<Kick> {
    if units.is_empty() {
        None
    } else if !changed.is_empty() {
        Some(Kick::Restart)
    } else {
        before
    }
}

/// Starts or restarts each unit through `socket`. Units the host lacks are
/// returned, to log; any other failure is an error, and the whole kick is
/// owed again (a second restart of a unit is harmless).
pub fn kick(socket: &Path, units: &[String], k: Kick) -> anyhow::Result<Vec<String>> {
    let mut absent = Vec::new();
    for u in units {
        match crate::systemd::call(socket, k.method(), u)? {
            crate::systemd::Outcome::Queued => info!("Asked systemd to {} {u}", k.method()),
            crate::systemd::Outcome::Absent(why) => absent.push(format!("{u}: {why}")),
        }
    }
    Ok(absent)
}

/// One pass: what it changed (empty: nothing).
pub fn install(o: &Options) -> anyhow::Result<Vec<String>> {
    let src = o.keytabs.join(format!("{}.keytab", o.node));
    let ours = std::fs::read(&src).with_context(|| format!("no keys for node {} yet ({})", o.node, src.display()))?;
    let host = match std::fs::read(&o.keytab) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", o.keytab.display())),
    };
    let mut changed = Vec::new();
    if write_if_changed(&o.keytab, &merge(&host, &ours)?, 0o600)? {
        changed.push(o.keytab.display().to_string());
    }
    if let Some(conf) = &o.krb5_conf {
        let data = std::fs::read(o.keytabs.join(crate::principal::KRB5_CONF_KEY)).context("no krb5.conf yet")?;
        if write_if_changed(conf, &data, 0o644)? {
            changed.push(conf.display().to_string());
        }
    }
    Ok(changed)
}

fn ready_mark() -> PathBuf {
    Path::new(crate::node::STATE_DIR).join("ready")
}

/// `node-agent-ready`, the readiness probe: whether the last pass worked.
pub fn ready() -> bool {
    ready_mark().exists()
}

fn parse(args: &[String]) -> anyhow::Result<Options> {
    let mut o = Options {
        keytabs: PathBuf::from(crate::node::KEYTABS_DIR),
        node: std::env::var("NODE_NAME").unwrap_or_default(),
        keytab: PathBuf::from("/etc/krb5.keytab"),
        krb5_conf: None,
        restart: Vec::new(),
        systemd: PathBuf::from("/run/systemd/private"),
    };
    for a in args {
        match a.split_once('=') {
            Some(("--keytabs", v)) => o.keytabs = v.into(),
            Some(("--keytab", v)) => o.keytab = v.into(),
            Some(("--krb5-conf", v)) => o.krb5_conf = Some(v.into()),
            Some(("--node", v)) => o.node = v.into(),
            Some(("--restart", v)) => match crate::systemd::service_unit(v) {
                Some(u) => o.restart.push(u),
                None => bail!("--restart={v:?}: not a service unit name"),
            },
            Some(("--systemd", v)) => o.systemd = v.into(),
            _ => bail!("unknown argument {a:?} (--keytabs= --keytab= --krb5-conf= --node= --restart= --systemd=)"),
        }
    }
    if o.node.is_empty() {
        bail!("no node: set NODE_NAME or --node");
    }
    Ok(o)
}

/// Install, then again every few seconds, until SIGTERM.
pub async fn run(args: &[String]) -> anyhow::Result<()> {
    let o = parse(args)?;
    info!("node-agent for node {}: keys into {}", o.node, o.keytab.display());
    if !o.restart.is_empty() {
        info!("Starting {} now, restarting them when a file changes", o.restart.join(", "));
    }
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut last_error = String::new();
    let mut logged_absent = Vec::new();
    let mut pending = owed(Some(Kick::Start), &[], &o.restart);
    loop {
        let pass = install(&o).and_then(|changed| {
            for c in &changed {
                info!("Installed {c}");
            }
            pending = owed(pending, &changed, &o.restart);
            if let Some(k) = pending {
                let absent = kick(&o.systemd, &o.restart, k)?;
                pending = None;
                if absent != logged_absent {
                    for a in &absent {
                        warn!("Not on this host, so not (re)started: {a}");
                    }
                    logged_absent = absent;
                }
            }
            Ok(())
        });
        match pass {
            Ok(()) => {
                if !ready() {
                    std::fs::write(ready_mark(), b"")?;
                }
                last_error.clear();
            }
            Err(e) => {
                let _ = std::fs::remove_file(ready_mark());
                // The pass may have written a file before it failed (or the
                // kick failed): restart once a pass works.
                pending = owed(pending, &["?".to_string()], &o.restart);
                let e = format!("{e:#}");
                if e != last_error {
                    warn!("{e}");
                    last_error = e;
                }
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            _ = term.recv() => return Ok(()),
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A keytab entry as MIT writes it: `name` in `realm`, `enctype`, `key`.
    fn entry(realm: &str, name: &[&str], enctype: u16, key: &[u8]) -> Vec<u8> {
        let s = |b: &mut Vec<u8>, v: &[u8]| {
            b.extend((v.len() as u16).to_be_bytes());
            b.extend(v);
        };
        let mut e = (name.len() as u16).to_be_bytes().to_vec();
        s(&mut e, realm.as_bytes());
        for c in name {
            s(&mut e, c.as_bytes());
        }
        e.extend(1u32.to_be_bytes()); // KRB5_NT_PRINCIPAL
        e.extend(0x6000_0000u32.to_be_bytes()); // timestamp
        e.push(3); // kvno
        e.extend(enctype.to_be_bytes());
        s(&mut e, key);
        e
    }

    fn keytab(es: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![5, 2];
        for e in es {
            out.extend((e.len() as i32).to_be_bytes());
            out.extend(e);
        }
        out
    }

    fn realms(kt: &[u8]) -> Vec<String> {
        entries(kt).unwrap().into_iter().map(|e| e.realm).collect()
    }

    #[test]
    fn the_operators_keytabs_parse() {
        let k = krb5::Key::new(18, vec![7; 32]).unwrap();
        let p = krb5::Principal::parse("host/w1.corp.example@CORP.TEST").unwrap();
        let kt = crate::principal::keytab(&[(p, vec![(2, k)])]).to_bytes();
        let es = entries(&kt).unwrap();
        assert_eq!(es.len(), 1);
        assert_eq!(es[0].realm, "CORP.TEST");
    }

    #[test]
    fn other_realms_entries_are_kept_byte_for_byte() {
        // The node's own keytab: an AD realm's rc4 key (an enctype the
        // krb5 crate does not know) and an old key of our realm.
        let ad = entry("AD.CORP", &["host", "w1"], 23, &[1; 16]);
        let old = entry("CORP.TEST", &["host", "w1"], 18, &[2; 32]);
        let host = keytab(&[ad.clone(), old]);
        let new = entry("CORP.TEST", &["host", "w1"], 18, &[3; 32]);
        let nfs = entry("CORP.TEST", &["nfs", "w1"], 18, &[4; 32]);
        let ours = keytab(&[new.clone(), nfs.clone()]);
        let merged = merge(&host, &ours).unwrap();
        assert_eq!(merged, keytab(&[ad.clone(), new, nfs]), "the AD entry kept, ours replaced");
        // Again: nothing changes.
        assert_eq!(merge(&merged, &ours).unwrap(), merged);
        // No host keytab yet: ours alone.
        assert_eq!(merge(&[], &ours).unwrap(), ours);
        assert_eq!(realms(&merged), vec!["AD.CORP", "CORP.TEST", "CORP.TEST"]);
    }

    #[test]
    fn deleted_entries_go_and_garbage_is_refused() {
        let a = entry("X.TEST", &["a"], 18, &[1; 32]);
        let mut kt = vec![5, 2];
        kt.extend((-(a.len() as i32)).to_be_bytes());
        kt.extend(&a);
        kt.extend((a.len() as i32).to_be_bytes());
        kt.extend(&a);
        assert_eq!(entries(&kt).unwrap().len(), 1, "the hole is dropped");
        assert!(entries(&[5, 1, 0, 0]).is_err(), "version 0x501");
        assert!(entries(b"[libdefaults]").is_err());
        let mut short = keytab(&[a]);
        short.truncate(short.len() - 3);
        assert!(entries(&short).is_err());
        assert!(merge(b"not a keytab", &keytab(&[])).is_err(), "a host file that is not a keytab is left alone");
    }

    #[test]
    fn install_merges_writes_once_and_privately() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let (src, host) = (d.path().join("secret"), d.path().join("etc"));
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&host).unwrap();
        let o = Options {
            keytabs: src.clone(),
            node: "w1".into(),
            keytab: host.join("krb5.keytab"),
            krb5_conf: Some(host.join("krb5.conf")),
            restart: Vec::new(),
            systemd: PathBuf::new(),
        };
        assert!(install(&o).unwrap_err().to_string().contains("no keys for node w1"));
        let ad = entry("AD.CORP", &["host", "w1"], 23, &[1; 16]);
        std::fs::write(&o.keytab, keytab(&[ad])).unwrap();
        let ours = keytab(&[entry("CORP.TEST", &["host", "w1"], 18, &[3; 32])]);
        std::fs::write(src.join("w1.keytab"), &ours).unwrap();
        std::fs::write(src.join("other.keytab"), keytab(&[entry("CORP.TEST", &["host", "w2"], 18, &[9; 32])])).unwrap();
        std::fs::write(src.join("krb5.conf"), "[libdefaults]\n").unwrap();
        assert_eq!(install(&o).unwrap().len(), 2);
        let kt = std::fs::read(&o.keytab).unwrap();
        assert_eq!(realms(&kt), vec!["AD.CORP", "CORP.TEST"]);
        assert!(!kt.windows(32).any(|w| w == [9; 32]), "another node's key is not installed");
        assert_eq!(std::fs::metadata(&o.keytab).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(host.join("krb5.conf")).unwrap().permissions().mode() & 0o777, 0o644);
        // Nothing changed: nothing written.
        assert!(install(&o).unwrap().is_empty());
        // A new key replaces ours.
        std::fs::write(src.join("w1.keytab"), keytab(&[entry("CORP.TEST", &["host", "w1"], 18, &[5; 32])])).unwrap();
        assert_eq!(install(&o).unwrap(), vec![o.keytab.display().to_string()]);
        let kt = std::fs::read(&o.keytab).unwrap();
        assert!(kt.windows(32).any(|w| w == [5; 32]) && !kt.windows(32).any(|w| w == [3; 32]));
        // No temporary file left behind.
        assert_eq!(std::fs::read_dir(&host).unwrap().count(), 2);
        // A host keytab that is not a keytab is not overwritten.
        std::fs::write(&o.keytab, b"garbage").unwrap();
        assert!(install(&o).is_err());
        assert_eq!(std::fs::read(&o.keytab).unwrap(), b"garbage");
    }

    #[test]
    fn arguments() {
        let o = parse(&["--keytab=/host/k".into(), "--node=w9".into(), "--krb5-conf=/host/c".into()]).unwrap();
        assert_eq!((o.keytab, o.node, o.krb5_conf), ("/host/k".into(), "w9".into(), Some("/host/c".into())));
        assert!(parse(&["--bogus".into()]).is_err());
        assert!(o.restart.is_empty(), "nothing restarted unless asked");
        let o = parse(&[
            "--node=w9".into(),
            "--restart=rpc-gssd".into(),
            "--restart=gssproxy.service".into(),
            "--systemd=/host/systemd/private".into(),
        ])
        .unwrap();
        assert_eq!(o.restart, vec!["rpc-gssd.service", "gssproxy.service"]);
        assert_eq!(o.systemd, PathBuf::from("/host/systemd/private"));
        assert!(parse(&["--node=w9".into(), "--restart=nfs-client.target".into()]).is_err());
        assert!(parse(&["--node=w9".into(), "--restart=a;reboot".into()]).is_err());
    }

    #[test]
    fn units_are_started_once_and_restarted_when_a_file_changes() {
        let units = vec!["rpc-gssd.service".to_string()];
        let changed = vec!["/host/keytab/krb5.keytab".to_string()];
        // The agent starts owing a start.
        assert_eq!(owed(Some(Kick::Start), &[], &units), Some(Kick::Start));
        assert_eq!(owed(Some(Kick::Start), &changed, &units), Some(Kick::Restart), "a restart outranks it");
        // Done, nothing changed: nothing owed.
        assert_eq!(owed(None, &[], &units), None);
        assert_eq!(owed(None, &changed, &units), Some(Kick::Restart), "a rotated key");
        assert_eq!(owed(Some(Kick::Restart), &[], &units), Some(Kick::Restart), "a failed restart is owed still");
        // No units: never anything.
        assert_eq!(owed(Some(Kick::Start), &changed, &[]), None);
    }

    #[test]
    fn a_kick_through_a_missing_socket_fails_so_it_is_owed_again() {
        let d = tempfile::tempdir().unwrap();
        let units = vec!["rpc-gssd.service".to_string()];
        assert!(kick(&d.path().join("private"), &units, Kick::Start).is_err());
        assert!(kick(&d.path().join("private"), &[], Kick::Start).unwrap().is_empty(), "no units, no call");
    }
}
