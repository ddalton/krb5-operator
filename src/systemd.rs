//! Asking the host's systemd to (re)start a unit, for `node-agent
//! --restart`: one D-Bus method call over systemd's private socket
//! (`/run/systemd/private`, what `systemctl` itself uses as root), which
//! the agent's pod mounts from the host.
//!
//! Why this and not `nsenter -t 1 ... systemctl`: the socket is one file;
//! nsenter needs the host's PID namespace and `CAP_SYS_ADMIN` (to enter the
//! host's mount namespace), and the image would need the host's systemctl.
//! The socket admits only uid 0, which the agent already is; it needs no
//! capability. It is still the host's service manager (it starts anything),
//! so the agent asks it for the units the spec names and nothing else, and
//! the operator mounts it only when `restartServices` is set.
//!
//! The client is the smallest D-Bus that does this: `AUTH EXTERNAL` with
//! the caller's uid, then a method call `(ss)` on
//! `org.freedesktop.systemd1.Manager`, then the reply with that serial.
//! systemd's private socket is a direct connection: no bus daemon, no
//! `Hello`. Little-endian messages, header fields of types `o s g u`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, bail};

const METHOD_CALL: u8 = 1;
const METHOD_RETURN: u8 = 2;
const ERROR: u8 = 3;

const PATH: u8 = 1;
const INTERFACE: u8 = 2;
const MEMBER: u8 = 3;
const ERROR_NAME: u8 = 4;
const REPLY_SERIAL: u8 = 5;
const DESTINATION: u8 = 6;
const SIGNATURE: u8 = 8;

/// Larger than any reply systemd sends to these calls.
const MAX_PART: usize = 1 << 20;

/// What a header field holds.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `o`
    Path(String),
    /// `s`
    Str(String),
    /// `g`
    Sig(String),
    /// `u`
    U32(u32),
}

/// A D-Bus message: its type, serial, header fields and marshalled body.
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    pub kind: u8,
    pub serial: u32,
    pub fields: Vec<(u8, Value)>,
    pub body: Vec<u8>,
}

impl Message {
    fn field(&self, code: u8) -> Option<&Value> {
        self.fields.iter().find(|(c, _)| *c == code).map(|(_, v)| v)
    }

    fn str_field(&self, code: u8) -> Option<&str> {
        match self.field(code)? {
            Value::Str(s) | Value::Path(s) | Value::Sig(s) => Some(s),
            Value::U32(_) => None,
        }
    }

    fn reply_serial(&self) -> Option<u32> {
        match self.field(REPLY_SERIAL)? {
            Value::U32(n) => Some(*n),
            _ => None,
        }
    }
}

/// A little-endian D-Bus marshaller. Offsets are from the message's start,
/// which is what alignment is relative to.
#[derive(Default)]
struct Out(Vec<u8>);

impl Out {
    fn pad(&mut self, n: usize) {
        while !self.0.len().is_multiple_of(n) {
            self.0.push(0);
        }
    }
    fn u32(&mut self, v: u32) {
        self.pad(4);
        self.0.extend(v.to_le_bytes());
    }
    /// `s` and `o`: length, bytes, NUL.
    fn str(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.0.extend(s.as_bytes());
        self.0.push(0);
    }
    /// `g`: one byte of length, bytes, NUL.
    fn sig(&mut self, s: &str) {
        self.0.push(s.len() as u8);
        self.0.extend(s.as_bytes());
        self.0.push(0);
    }
}

/// The body of a call with signature `ss`.
pub fn body_ss(a: &str, b: &str) -> Vec<u8> {
    // A body starts 8-aligned, so its own offsets align the same way.
    let mut o = Out::default();
    o.str(a);
    o.str(b);
    o.0
}

/// `m` on the wire (little-endian, protocol version 1).
pub fn encode(m: &Message) -> Vec<u8> {
    let mut o = Out::default();
    o.0.extend([b'l', m.kind, 0, 1]);
    o.u32(m.body.len() as u32);
    o.u32(m.serial);
    // The header fields: an array of (byte, variant), its length in bytes
    // from its first element (8-aligned, at offset 16) to its last's end.
    o.u32(0);
    o.pad(8);
    let start = o.0.len();
    for (code, v) in &m.fields {
        o.pad(8);
        o.0.push(*code);
        match v {
            Value::Path(s) => {
                o.sig("o");
                o.str(s);
            }
            Value::Str(s) => {
                o.sig("s");
                o.str(s);
            }
            Value::Sig(s) => {
                o.sig("g");
                o.sig(s);
            }
            Value::U32(n) => {
                o.sig("u");
                o.u32(*n);
            }
        }
    }
    let len = (o.0.len() - start) as u32;
    o.0[12..16].copy_from_slice(&len.to_le_bytes());
    o.pad(8);
    o.0.extend(&m.body);
    o.0
}

/// Reads the D-Bus types the header and an error's body use, either byte
/// order. `at` is the offset in the message.
struct In<'a> {
    data: &'a [u8],
    at: usize,
    big: bool,
}

impl In<'_> {
    fn align(&mut self, n: usize) {
        self.at = self.at.div_ceil(n) * n;
    }
    fn take(&mut self, n: usize) -> anyhow::Result<&[u8]> {
        let b = self.data.get(self.at..self.at + n).context("a truncated D-Bus message")?;
        self.at += n;
        Ok(b)
    }
    fn byte(&mut self) -> anyhow::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> anyhow::Result<u32> {
        self.align(4);
        let b: [u8; 4] = self.take(4)?.try_into().expect("4 bytes");
        Ok(if self.big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
    }
    fn nul_terminated(&mut self, n: usize) -> anyhow::Result<String> {
        let s = String::from_utf8_lossy(self.take(n)?).into_owned();
        if self.byte()? != 0 {
            bail!("a D-Bus string without its NUL");
        }
        Ok(s)
    }
    fn str(&mut self) -> anyhow::Result<String> {
        let n = self.u32()? as usize;
        self.nul_terminated(n)
    }
    fn sig(&mut self) -> anyhow::Result<String> {
        let n = self.byte()? as usize;
        self.nul_terminated(n)
    }
}

/// One message from `r`.
pub fn read_message(r: &mut impl Read) -> anyhow::Result<Message> {
    let mut fixed = [0u8; 16];
    r.read_exact(&mut fixed).context("reading a D-Bus message")?;
    let big = match fixed[0] {
        b'l' => false,
        b'B' => true,
        e => bail!("not a D-Bus message (endianness {e:#x})"),
    };
    let word = |i: usize| {
        let b: [u8; 4] = fixed[i..i + 4].try_into().expect("4 bytes");
        (if big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }) as usize
    };
    let (body_len, serial, fields_len) = (word(4), word(8) as u32, word(12));
    if body_len > MAX_PART || fields_len > MAX_PART {
        bail!("a D-Bus message too large ({fields_len} + {body_len} bytes)");
    }
    let header_end = (16 + fields_len).div_ceil(8) * 8;
    let mut data = fixed.to_vec();
    data.resize(header_end + body_len, 0);
    r.read_exact(&mut data[16..]).context("reading a D-Bus message")?;
    let mut i = In { data: &data[..16 + fields_len], at: 16, big };
    let mut fields = Vec::new();
    while i.at < 16 + fields_len {
        i.align(8);
        let code = i.byte()?;
        let v = match i.sig()?.as_str() {
            "o" => Value::Path(i.str()?),
            "s" => Value::Str(i.str()?),
            "g" => Value::Sig(i.sig()?),
            "u" => Value::U32(i.u32()?),
            t => bail!("a D-Bus header field ({code}) of type {t:?}"),
        };
        fields.push((code, v));
    }
    Ok(Message { kind: fixed[1], serial, fields, body: data[header_end..].to_vec() })
}

/// The first string of a body whose signature starts with `s` (an error's
/// message).
fn first_string(m: &Message) -> Option<String> {
    if !m.str_field(SIGNATURE)?.starts_with('s') {
        return None;
    }
    // The body is 8-aligned in the message: align from 0 as it did.
    In { data: &m.body, at: 0, big: false }.str().ok()
}

/// `Manager.<method>(unit, "replace")`, the call `systemctl <verb> <unit>`
/// makes.
pub fn unit_call(method: &str, unit: &str, serial: u32) -> Message {
    Message {
        kind: METHOD_CALL,
        serial,
        fields: vec![
            (PATH, Value::Path("/org/freedesktop/systemd1".into())),
            (INTERFACE, Value::Str("org.freedesktop.systemd1.Manager".into())),
            (MEMBER, Value::Str(method.into())),
            (DESTINATION, Value::Str("org.freedesktop.systemd1".into())),
            (SIGNATURE, Value::Sig("ss".into())),
        ],
        body: body_ss(unit, "replace"),
    }
}

/// How systemd answered.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// It queued the job.
    Queued,
    /// The unit is not on this host (`NoSuchUnit`, `LoadFailed`) or is
    /// masked: nothing to (re)start.
    Absent(String),
}

/// The caller's real uid, which `AUTH EXTERNAL` names (hex of its decimal
/// digits). The server checks it against the socket's peer credentials.
fn uid() -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| l.strip_prefix("Uid:").and_then(|u| u.split_whitespace().next().map(String::from)))
        })
        .unwrap_or_else(|| "0".into())
}

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

/// Reads one `\r\n`-terminated line of the auth exchange.
fn auth_line(s: &mut impl Read) -> anyhow::Result<String> {
    let mut line = Vec::new();
    let mut b = [0u8];
    while !line.ends_with(b"\r\n") {
        s.read_exact(&mut b).context("reading systemd's answer to AUTH")?;
        line.push(b[0]);
        if line.len() > 512 {
            bail!("an AUTH line too long");
        }
    }
    line.truncate(line.len() - 2);
    Ok(String::from_utf8_lossy(&line).into_owned())
}

/// Calls `Manager.<method>(unit, "replace")` on the systemd listening at
/// `socket` (`StartUnit`, `RestartUnit`).
pub fn call(socket: &Path, method: &str, unit: &str) -> anyhow::Result<Outcome> {
    let mut s =
        UnixStream::connect(socket).with_context(|| format!("connecting to systemd at {}", socket.display()))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    // BEGIN goes with AUTH, as sd-bus's own client sends it, and the call
    // only after systemd's OK. A call written together with BEGIN lands in
    // systemd's (252) auth buffer, which it does not read again until some
    // other event wakes the connection: measured on kind, the call ran 4 s
    // late and its reply never came before our read timeout.
    s.write_all(format!("\0AUTH EXTERNAL {}\r\nBEGIN\r\n", hex(&uid())).as_bytes())?;
    let ok = auth_line(&mut s)?;
    if !ok.starts_with("OK ") {
        bail!("systemd refused the connection: {ok:?} (the agent must be uid 0)");
    }
    let serial = 1;
    s.write_all(&encode(&unit_call(method, unit, serial)))?;
    loop {
        let m = read_message(&mut s)?;
        if m.reply_serial() != Some(serial) || !matches!(m.kind, METHOD_RETURN | ERROR) {
            continue; // a signal, or someone else's reply
        }
        if m.kind == METHOD_RETURN {
            return Ok(Outcome::Queued);
        }
        let name = m.str_field(ERROR_NAME).unwrap_or("an unnamed error").to_string();
        let text = first_string(&m).unwrap_or_default();
        return match name.as_str() {
            "org.freedesktop.systemd1.NoSuchUnit"
            | "org.freedesktop.systemd1.UnitMasked"
            | "org.freedesktop.systemd1.LoadFailed" => Ok(Outcome::Absent(format!("{name}: {text}"))),
            _ => bail!("systemd {method} {unit}: {name}: {text}"),
        };
    }
}

/// A systemd unit name for a service: `[A-Za-z0-9:_.\-@]`, `.service`
/// appended when it has no suffix; an instance (`a@b`), not a template
/// (`a@`).
pub fn service_unit(name: &str) -> Option<String> {
    let unit = if name.ends_with(".service") { name.to_string() } else { format!("{name}.service") };
    let stem = unit.strip_suffix(".service")?;
    let ok = !stem.is_empty()
        && unit.len() <= 255
        && !stem.contains('.')
        && !stem.ends_with('@')
        && !stem.starts_with('@')
        && stem.matches('@').count() <= 1
        && stem.bytes().all(|b| b.is_ascii_alphanumeric() || b":_-@\\".contains(&b));
    ok.then_some(unit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn a_call_is_marshalled_as_the_spec_says() {
        let m = unit_call("RestartUnit", "rpc-gssd.service", 1);
        let b = encode(&m);
        assert_eq!(&b[..4], &[b'l', 1, 0, 1], "little-endian, METHOD_CALL, no flags, version 1");
        let body = body_ss("rpc-gssd.service", "replace");
        // 4 + 16 + NUL, padded to 4, then 4 + 7 + NUL.
        assert_eq!(body.len(), 4 + 17 + 3 + 4 + 8);
        assert_eq!(&body[..4], &16u32.to_le_bytes());
        assert_eq!(&body[24..28], &7u32.to_le_bytes());
        assert_eq!(&b[4..8], &(body.len() as u32).to_le_bytes());
        assert_eq!(&b[8..12], &1u32.to_le_bytes(), "the serial");
        let fields_len = u32::from_le_bytes(b[12..16].try_into().unwrap()) as usize;
        let header_end = (16 + fields_len).div_ceil(8) * 8;
        assert_eq!(b.len(), header_end + body.len());
        assert_eq!(&b[header_end..], &body[..]);
        // The first field: PATH, signature "o", then the path 4-aligned.
        assert_eq!(&b[16..20], &[PATH, 1, b'o', 0]);
        assert_eq!(&b[20..24], &25u32.to_le_bytes());
        assert_eq!(&b[24..49], b"/org/freedesktop/systemd1");
        assert_eq!(b[49], 0);
        // The next field starts 8-aligned.
        assert_eq!(&b[56..60], &[INTERFACE, 1, b's', 0]);
        assert_eq!(read_message(&mut &b[..]).unwrap(), m, "it reads back");
    }

    #[test]
    fn big_endian_and_garbage() {
        // A big-endian METHOD_RETURN, REPLY_SERIAL 7, no body.
        let mut b = vec![b'B', METHOD_RETURN, 0, 1, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 8];
        b.extend([REPLY_SERIAL, 1, b'u', 0, 0, 0, 0, 7]);
        let m = read_message(&mut &b[..]).unwrap();
        assert_eq!((m.kind, m.serial, m.reply_serial()), (METHOD_RETURN, 9, Some(7)));
        assert!(read_message(&mut &b"GET / HTTP/1.1\r\n\r\n"[..]).is_err());
        assert!(read_message(&mut &b[..20]).is_err(), "truncated");
        let mut huge = b.clone();
        huge[4..8].copy_from_slice(&[0x7f, 0, 0, 0]);
        assert!(read_message(&mut &huge[..]).is_err());
    }

    #[test]
    fn service_units() {
        assert_eq!(service_unit("rpc-gssd").as_deref(), Some("rpc-gssd.service"));
        assert_eq!(service_unit("rpc-gssd.service").as_deref(), Some("rpc-gssd.service"));
        assert_eq!(service_unit("gssproxy").as_deref(), Some("gssproxy.service"));
        assert_eq!(service_unit("getty@tty1").as_deref(), Some("getty@tty1.service"));
        for bad in ["", ".service", "a b", "a/b", "nfs-client.target", "getty@", "getty@.service", "@x", "a;b", "a$"] {
            assert_eq!(service_unit(bad), None, "{bad:?}");
        }
    }

    /// A systemd stand-in at a socket in `dir`: checks the auth exchange,
    /// records each call's member and unit, answers with `answer(unit)`
    /// (`None`: a method return), after a signal to show it is skipped.
    fn fake_systemd(
        dir: &Path,
        answer: fn(&str) -> Option<(&'static str, &'static str)>,
    ) -> (std::path::PathBuf, std::sync::mpsc::Receiver<(String, String)>) {
        let path = dir.join("private");
        let l = UnixListener::bind(&path).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let mut c = c.unwrap();
                let mut nul = [0u8];
                c.read_exact(&mut nul).unwrap();
                assert_eq!(nul[0], 0, "a NUL byte first");
                let auth = auth_line(&mut c).unwrap();
                assert_eq!(auth, format!("AUTH EXTERNAL {}", hex(&uid())));
                c.write_all(b"OK 0123456789abcdef0123456789abcdef\r\n").unwrap();
                assert_eq!(auth_line(&mut c).unwrap(), "BEGIN");
                let call = read_message(&mut c).unwrap();
                assert_eq!(call.kind, METHOD_CALL);
                assert_eq!(call.str_field(PATH), Some("/org/freedesktop/systemd1"));
                assert_eq!(call.str_field(INTERFACE), Some("org.freedesktop.systemd1.Manager"));
                assert_eq!(call.str_field(SIGNATURE), Some("ss"));
                let mut b = In { data: &call.body, at: 0, big: false };
                let (unit, mode) = (b.str().unwrap(), b.str().unwrap());
                assert_eq!(mode, "replace");
                let member = call.str_field(MEMBER).unwrap().to_string();
                let signal = Message {
                    kind: 4,
                    serial: 1,
                    fields: vec![(PATH, Value::Path("/org/freedesktop/systemd1".into()))],
                    body: vec![],
                };
                c.write_all(&encode(&signal)).unwrap();
                let reply = match answer(&unit) {
                    None => Message {
                        kind: METHOD_RETURN,
                        serial: 2,
                        fields: vec![(REPLY_SERIAL, Value::U32(call.serial)), (SIGNATURE, Value::Sig("o".into()))],
                        body: {
                            let mut o = Out::default();
                            o.str("/org/freedesktop/systemd1/job/42");
                            o.0
                        },
                    },
                    Some((name, text)) => Message {
                        kind: ERROR,
                        serial: 2,
                        fields: vec![
                            (ERROR_NAME, Value::Str(name.into())),
                            (REPLY_SERIAL, Value::U32(call.serial)),
                            (SIGNATURE, Value::Sig("s".into())),
                        ],
                        body: {
                            let mut o = Out::default();
                            o.str(text);
                            o.0
                        },
                    },
                };
                c.write_all(&encode(&reply)).unwrap();
                tx.send((member, unit)).unwrap();
            }
        });
        (path, rx)
    }

    #[test]
    fn units_are_restarted_and_absent_ones_skipped() {
        let d = tempfile::tempdir().unwrap();
        let (sock, calls) = fake_systemd(d.path(), |unit| match unit {
            "rpc-gssd.service" => None,
            "gone.service" => Some(("org.freedesktop.systemd1.NoSuchUnit", "Unit gone.service not found.")),
            "masked.service" => Some(("org.freedesktop.systemd1.UnitMasked", "Unit masked.service is masked.")),
            _ => Some(("org.freedesktop.DBus.Error.AccessDenied", "no")),
        });
        assert_eq!(call(&sock, "RestartUnit", "rpc-gssd.service").unwrap(), Outcome::Queued);
        assert_eq!(calls.recv().unwrap(), ("RestartUnit".into(), "rpc-gssd.service".into()));
        assert_eq!(call(&sock, "StartUnit", "rpc-gssd.service").unwrap(), Outcome::Queued);
        assert_eq!(calls.recv().unwrap().0, "StartUnit");
        let Outcome::Absent(why) = call(&sock, "RestartUnit", "gone.service").unwrap() else { panic!() };
        assert!(why.contains("NoSuchUnit") && why.contains("not found"), "{why}");
        assert!(matches!(call(&sock, "RestartUnit", "masked.service").unwrap(), Outcome::Absent(_)));
        let e = call(&sock, "RestartUnit", "other.service").unwrap_err().to_string();
        assert!(e.contains("AccessDenied"), "{e}");
    }

    #[test]
    fn no_systemd_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        assert!(call(&d.path().join("private"), "StartUnit", "rpc-gssd.service").is_err());
    }
}
