//! The transport a DbgRpc connection runs over, and the endpoint string a
//! host names it with.
//!
//! `tcp:server=<host>,port=<port>` and `npipe:[server=<host>,]pipe=<name>`
//! (Windows) are supported, each with an optional `password=<secret>` (sent
//! during the handshake as a Base64-encoded UTF-16LE buffer, matching
//! `dbgeng.dll`). DbgRpc's encrypted transports (`ssl`, `spipe`) and hardware
//! transports (`1394`, `com`) are refused with an explicit error rather than
//! silently ignored.

use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[cfg(windows)]
use crate::backend::kd::PipeStream;
use crate::base::error::{Error, Result};

use super::wire::hash_password;

/// How long a connection attempt (and the initial handshake) may take before
/// it fails.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A DbgRpc endpoint.
#[derive(Clone, PartialEq, Eq)]
pub enum DbgsrvEndpoint {
    /// `tcp:server=<host>,port=<port>[,password=<secret>]`.
    Tcp {
        server: String,
        port: u16,
        password: Option<String>,
    },
    /// `npipe:[server=<host>,]pipe=<name>[,password=<secret>]`.
    NamedPipe {
        server: String,
        pipe: String,
        password: Option<String>,
    },
}

impl DbgsrvEndpoint {
    /// The connection password, when one was supplied.
    pub fn password(&self) -> Option<&str> {
        match self {
            Self::Tcp { password, .. } | Self::NamedPipe { password, .. } => password.as_deref(),
        }
    }

    /// The full UNC path for a named-pipe endpoint (`\\<server>\pipe\<pipe>`,
    /// or `pipe` verbatim when it already starts with `\`, matching
    /// `DbgRpcNamedPipeTransport::ConnectServer`).
    pub fn pipe_path(&self) -> Option<String> {
        let Self::NamedPipe { server, pipe, .. } = self else {
            return None;
        };
        if pipe.starts_with('\\') {
            Some(pipe.clone())
        } else {
            Some(format!(r"\\{server}\pipe\{pipe}"))
        }
    }

    /// Password-free destination label for progress messages and error text.
    pub fn target_label(&self) -> String {
        match self {
            Self::Tcp { server, port, .. } => format!("{server}:{port}"),
            Self::NamedPipe { .. } => self.pipe_path().unwrap_or_default(),
        }
    }

    /// Open the transport. DbgRpc's TCP and named-pipe transports are bare byte
    /// streams with no framing of their own, so header and body writes must be
    /// ordered by the caller, which one lock over the connection does.
    pub fn connect(&self) -> Result<Transport> {
        match self {
            Self::Tcp { server, port, .. } => {
                let address = format!("{server}:{port}");
                let stream = TcpStream::connect(&address).map_err(|error| {
                    Error::Dbgsrv(format!("cannot connect to {address}: {error}"))
                })?;
                stream.set_nodelay(true).ok();
                stream
                    .set_read_timeout(Some(CONNECT_TIMEOUT))
                    .map_err(|error| {
                        Error::Dbgsrv(format!("cannot configure {address}: {error}"))
                    })?;
                Ok(Transport {
                    stream: Stream::Tcp(stream),
                    address,
                    timeout: Some(CONNECT_TIMEOUT),
                })
            }
            Self::NamedPipe { .. } => {
                let path = self.pipe_path().unwrap_or_default();
                #[cfg(windows)]
                {
                    let stream =
                        PipeStream::open_once(&path, CONNECT_TIMEOUT).map_err(|error| {
                            Error::Dbgsrv(format!("cannot connect to {path}: {error}"))
                        })?;
                    stream
                        .set_read_timeout(Some(CONNECT_TIMEOUT))
                        .map_err(|error| {
                            Error::Dbgsrv(format!("cannot configure {path}: {error}"))
                        })?;
                    Ok(Transport {
                        stream: Stream::Pipe(stream),
                        address: path,
                        timeout: Some(CONNECT_TIMEOUT),
                    })
                }
                #[cfg(not(windows))]
                {
                    let _ = path;
                    Err(Error::Dbgsrv(
                        "dbgsrv named-pipe endpoints are only supported on Windows".to_string(),
                    ))
                }
            }
        }
    }
}

impl fmt::Display for DbgsrvEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp {
                server,
                port,
                password,
            } => {
                write!(f, "tcp:server={server},port={port}")?;
                if password.is_some() {
                    write!(f, ",password=*")?;
                }
                Ok(())
            }
            Self::NamedPipe {
                server,
                pipe,
                password,
            } => {
                write!(f, "npipe:server={server},pipe={pipe}")?;
                if password.is_some() {
                    write!(f, ",password=*")?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Debug for DbgsrvEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp {
                server,
                port,
                password,
            } => f
                .debug_struct("Tcp")
                .field("server", server)
                .field("port", port)
                .field("password", &password.as_ref().map(|_| "*"))
                .finish(),
            Self::NamedPipe {
                server,
                pipe,
                password,
            } => f
                .debug_struct("NamedPipe")
                .field("server", server)
                .field("pipe", pipe)
                .field("password", &password.as_ref().map(|_| "*"))
                .finish(),
        }
    }
}

/// Parse a `cdb -premote`-style DbgRpc endpoint string passed as `connect`.
pub fn parse_endpoint(value: &str) -> Result<DbgsrvEndpoint> {
    let invalid = |message: String| Err(Error::InvalidArgument(message));
    let (transport, parameters) = value.split_once(':').ok_or_else(|| {
        Error::InvalidArgument(format!(
            "dbgsrv endpoint '{value}' names no transport: expected \
             tcp:server=<host>,port=<port> or npipe:[server=<host>,]pipe=<name>"
        ))
    })?;
    let kind = if transport.eq_ignore_ascii_case("tcp") {
        EndpointKind::Tcp
    } else if transport.eq_ignore_ascii_case("npipe") {
        EndpointKind::NamedPipe
    } else if transport.eq_ignore_ascii_case("ssl") || transport.eq_ignore_ascii_case("spipe") {
        return invalid("dbgsrv secure transports (ssl/spipe) are not supported".to_string());
    } else if transport.eq_ignore_ascii_case("1394") || transport.eq_ignore_ascii_case("com") {
        return invalid(format!(
            "dbgsrv transport '{transport}' is not supported; use \
             tcp:server=<host>,port=<port> or npipe:[server=<host>,]pipe=<name>"
        ));
    } else {
        return invalid(format!(
            "unknown dbgsrv transport '{transport}': expected \
             tcp:server=<host>,port=<port> or npipe:[server=<host>,]pipe=<name>"
        ));
    };

    let mut server: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut pipe: Option<String> = None;
    let mut password: Option<String> = None;

    for parameter in parameters.split(',').filter(|part| !part.is_empty()) {
        let (name, val) = parameter.split_once('=').ok_or_else(|| {
            Error::InvalidArgument(format!(
                "dbgsrv endpoint parameter '{parameter}' is not name=value"
            ))
        })?;
        if name.eq_ignore_ascii_case("server") {
            let trimmed = if kind == EndpointKind::NamedPipe {
                val.strip_prefix(r"\\").unwrap_or(val)
            } else {
                val
            };
            server = Some(trimmed.to_string());
        } else if name.eq_ignore_ascii_case("password") {
            // Validate length and non-emptiness up front before connecting.
            let _ = hash_password(val)?;
            password = Some(val.to_string());
        } else if kind == EndpointKind::Tcp && name.eq_ignore_ascii_case("port") {
            port = Some(val.parse::<u16>().map_err(|_| {
                Error::InvalidArgument(format!("dbgsrv endpoint port '{val}' is not a u16"))
            })?);
        } else if kind == EndpointKind::NamedPipe && name.eq_ignore_ascii_case("pipe") {
            pipe = Some(val.to_string());
        } else {
            let expected = match kind {
                EndpointKind::Tcp => "server, port, and optional password",
                EndpointKind::NamedPipe => "pipe, optional server, and optional password",
            };
            return invalid(format!(
                "unknown dbgsrv endpoint parameter '{name}': expected {expected}"
            ));
        }
    }

    match kind {
        EndpointKind::Tcp => {
            let server = server.filter(|server| !server.is_empty()).ok_or_else(|| {
                Error::InvalidArgument("dbgsrv endpoint names no server".to_string())
            })?;
            let port = port.ok_or_else(|| {
                Error::InvalidArgument("dbgsrv endpoint names no port".to_string())
            })?;
            Ok(DbgsrvEndpoint::Tcp {
                server,
                port,
                password,
            })
        }
        EndpointKind::NamedPipe => {
            let pipe = pipe.filter(|pipe| !pipe.is_empty()).ok_or_else(|| {
                Error::InvalidArgument("dbgsrv npipe endpoint names no pipe".to_string())
            })?;
            let server = match server {
                Some(s) if s.is_empty() => {
                    return invalid("dbgsrv endpoint names an empty server".to_string());
                }
                Some(s) => s,
                None => ".".to_string(),
            };
            Ok(DbgsrvEndpoint::NamedPipe {
                server,
                pipe,
                password,
            })
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EndpointKind {
    Tcp,
    NamedPipe,
}

enum Stream {
    Tcp(TcpStream),
    #[cfg(windows)]
    Pipe(PipeStream),
}

/// A connected DbgRpc stream (TCP socket or Windows named pipe).
pub struct Transport {
    stream: Stream,
    address: String,
    timeout: Option<Duration>,
}

impl Transport {
    /// Set the read timeout; `None` waits forever.
    ///
    /// [`crate::backend::dbgsrv::service::ProcessServer::wait_for_event`] is
    /// the one call that blocks on the server's timer, so it is the one that
    /// needs a timeout longer than any wait it asks for.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        self.timeout = timeout;
        let result = match &self.stream {
            Stream::Tcp(stream) => stream.set_read_timeout(timeout),
            #[cfg(windows)]
            Stream::Pipe(stream) => stream.set_read_timeout(timeout),
        };
        result.map_err(|error| Error::Dbgsrv(format!("cannot set timeout: {error}")))
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        let result = match &mut self.stream {
            Stream::Tcp(stream) => stream.read_exact(buf),
            #[cfg(windows)]
            Stream::Pipe(stream) => stream.read_exact(buf),
        };
        result.map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut
                || error.kind() == std::io::ErrorKind::WouldBlock
            {
                Error::Dbgsrv(format!(
                    "{} did not answer within {:?}",
                    self.address,
                    self.timeout.unwrap_or_default()
                ))
            } else {
                Error::Dbgsrv(format!("read from {} failed: {error}", self.address))
            }
        })
    }

    pub fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        let result = match &mut self.stream {
            Stream::Tcp(stream) => stream.write_all(buf),
            #[cfg(windows)]
            Stream::Pipe(stream) => stream.write_all(buf),
        };
        result.map_err(|error| Error::Dbgsrv(format!("write to {} failed: {error}", self.address)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_and_npipe_endpoints_parse_and_redact_passwords() {
        assert_eq!(
            parse_endpoint("tcp:server=10.0.0.5,port=5005").unwrap(),
            DbgsrvEndpoint::Tcp {
                server: "10.0.0.5".into(),
                port: 5005,
                password: None,
            }
        );
        assert_eq!(
            parse_endpoint("TCP:Port=5005,Server=debug-host,Password=Secret12").unwrap(),
            DbgsrvEndpoint::Tcp {
                server: "debug-host".into(),
                port: 5005,
                password: Some("Secret12".into()),
            }
        );
        let tcp_pwd = parse_endpoint("tcp:server=127.0.0.1,port=5005,password=Secret12").unwrap();
        assert_eq!(
            tcp_pwd.to_string(),
            "tcp:server=127.0.0.1,port=5005,password=*"
        );
        assert!(!format!("{tcp_pwd:?}").contains("Secret12"));

        let pipe_local = parse_endpoint("npipe:pipe=dbg1").unwrap();
        assert_eq!(
            pipe_local,
            DbgsrvEndpoint::NamedPipe {
                server: ".".into(),
                pipe: "dbg1".into(),
                password: None,
            }
        );
        assert_eq!(pipe_local.pipe_path().as_deref(), Some(r"\\.\pipe\dbg1"));

        let pipe_remote =
            parse_endpoint(r"NPIPE:server=\\WORKSTATION,pipe=dbg1,password=MyPass!").unwrap();
        assert_eq!(
            pipe_remote,
            DbgsrvEndpoint::NamedPipe {
                server: "WORKSTATION".into(),
                pipe: "dbg1".into(),
                password: Some("MyPass!".into()),
            }
        );
        assert_eq!(
            pipe_remote.pipe_path().as_deref(),
            Some(r"\\WORKSTATION\pipe\dbg1")
        );
        assert_eq!(
            pipe_remote.to_string(),
            "npipe:server=WORKSTATION,pipe=dbg1,password=*"
        );
        assert!(!format!("{pipe_remote:?}").contains("MyPass!"));

        let pipe_unc = parse_endpoint(r"npipe:pipe=\\.\pipe\custom").unwrap();
        assert_eq!(pipe_unc.pipe_path().as_deref(), Some(r"\\.\pipe\custom"));
    }

    #[test]
    fn secure_transports_and_malformed_endpoints_are_refused() {
        for endpoint in [
            "ssl:server=host,port=5005",
            "spipe:server=host,port=5005",
            "1394:channel=1",
            "com:port=com1",
            "tcp:server=host,port=not-a-port",
            "tcp:server=host,port=70000",
            "tcp:port=5005",
            "tcp:server=host",
            "tcp:server=host,prot=5005",
            "tcp:server=host,port",
            "tcp:server=host,port=5005,password=",
            "tcp:server=host,port=5005,password=1234567890123",
            "npipe:server=host",
            "npipe:pipe=",
            "npipe:server=,pipe=foo",
            "npipe:server=host,port=5005",
            "5005",
        ] {
            let error = parse_endpoint(endpoint)
                .expect_err("endpoint must be refused")
                .to_string();
            assert!(
                error.contains("dbgsrv") || error.contains("invalid"),
                "{endpoint}: {error}"
            );
        }
        assert!(
            parse_endpoint("ssl:server=host,port=5005")
                .unwrap_err()
                .to_string()
                .contains("not supported")
        );
    }
}
