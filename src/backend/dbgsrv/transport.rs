//! The transport a DbgRpc connection runs over, and the endpoint string a
//! host names it with.
//!
//! Only `tcp:server=<host>,port=<port>` is implemented. DbgRpc's other
//! transports (`npipe`, `ssl`, `spipe`, `1394`, `com`) and connect passwords
//! are refused with an explicit error rather than silently ignored: a
//! connection that drops a password, or falls back to clear text, would be a
//! security surprise.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::base::error::{Error, Result};

/// How long a connection attempt may take before it fails.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A DbgRpc endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DbgsrvEndpoint {
    /// `tcp:server=<host>,port=<port>`.
    Tcp { server: String, port: u16 },
}

impl std::fmt::Display for DbgsrvEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp { server, port } => write!(f, "tcp:server={server},port={port}"),
        }
    }
}

/// The one endpoint form a DbgRpc client can connect to, parsed from the
/// `cdb -premote`-style string a host passes as `connect`.
pub fn parse_endpoint(value: &str) -> Result<DbgsrvEndpoint> {
    let invalid = |message: String| Err(Error::InvalidArgument(message));
    let (transport, parameters) = value.split_once(':').ok_or_else(|| {
        Error::InvalidArgument(format!(
            "dbgsrv endpoint '{value}' names no transport: expected \
             tcp:server=<host>,port=<port>"
        ))
    })?;
    match transport {
        "tcp" => {}
        "npipe" => {
            return invalid(
                "dbgsrv named-pipe endpoints are not supported; use tcp:server=<host>,port=<port>"
                    .to_string(),
            );
        }
        "ssl" | "spipe" => {
            return invalid("dbgsrv secure transports/passwords are not supported".to_string());
        }
        "1394" | "com" => {
            return invalid(format!(
                "dbgsrv transport '{transport}' is not supported; use \
                 tcp:server=<host>,port=<port>"
            ));
        }
        other => {
            return invalid(format!(
                "unknown dbgsrv transport '{other}': expected tcp:server=<host>,port=<port>"
            ));
        }
    }
    let mut server: Option<String> = None;
    let mut port: Option<u16> = None;
    for parameter in parameters.split(',').filter(|part| !part.is_empty()) {
        let (name, value) = parameter.split_once('=').ok_or_else(|| {
            Error::InvalidArgument(format!(
                "dbgsrv endpoint parameter '{parameter}' is not name=value"
            ))
        })?;
        match name {
            "server" => server = Some(value.to_string()),
            "port" => {
                port = Some(value.parse::<u16>().map_err(|_| {
                    Error::InvalidArgument(format!("dbgsrv endpoint port '{value}' is not a u16"))
                })?)
            }
            "password" => {
                return invalid("dbgsrv secure transports/passwords are not supported".to_string());
            }
            other => {
                return invalid(format!(
                    "unknown dbgsrv endpoint parameter '{other}': expected server and port"
                ));
            }
        }
    }
    let server = server
        .filter(|server| !server.is_empty())
        .ok_or_else(|| Error::InvalidArgument("dbgsrv endpoint names no server".to_string()))?;
    let port =
        port.ok_or_else(|| Error::InvalidArgument("dbgsrv endpoint names no port".to_string()))?;
    Ok(DbgsrvEndpoint::Tcp { server, port })
}

impl DbgsrvEndpoint {
    /// Open the transport. DbgRpc's TCP transport is a bare byte stream: it
    /// has no framing of its own, so header and body writes must be ordered
    /// by the caller, which one lock over the connection does.
    pub fn connect(&self) -> Result<TcpTransport> {
        let Self::Tcp { server, port } = self;
        let address = format!("{server}:{port}");
        let stream = TcpStream::connect(&address).map_err(|error| {
            Error::DebugInfo(format!("dbgsrv: cannot connect to {address}: {error}"))
        })?;
        stream.set_nodelay(true).ok();
        stream
            .set_read_timeout(Some(CONNECT_TIMEOUT))
            .map_err(|error| {
                Error::DebugInfo(format!("dbgsrv: cannot configure {address}: {error}"))
            })?;
        Ok(TcpTransport {
            stream,
            address,
            timeout: Some(CONNECT_TIMEOUT),
        })
    }
}

/// A connected DbgRpc stream.
pub struct TcpTransport {
    stream: TcpStream,
    address: String,
    timeout: Option<Duration>,
}

impl TcpTransport {
    /// How the endpoint is named in messages.
    pub fn describe(&self) -> &str {
        &self.address
    }

    /// Set the read timeout; `None` waits forever.
    ///
    /// [`crate::backend::dbgsrv::service::ProcessServer::wait_for_event`] is
    /// the one call that blocks on the server's timer, so it is the one that
    /// needs a timeout longer than any wait it asks for.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        self.timeout = timeout;
        self.stream
            .set_read_timeout(timeout)
            .map_err(|error| Error::DebugInfo(format!("dbgsrv: cannot set timeout: {error}")))
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        self.stream.read_exact(buf).map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut
                || error.kind() == std::io::ErrorKind::WouldBlock
            {
                Error::DebugInfo(format!(
                    "dbgsrv: {} did not answer within {:?}",
                    self.address,
                    self.timeout.unwrap_or_default()
                ))
            } else {
                Error::DebugInfo(format!(
                    "dbgsrv: read from {} failed: {error}",
                    self.address
                ))
            }
        })
    }

    pub fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.stream.write_all(buf).map_err(|error| {
            Error::DebugInfo(format!("dbgsrv: write to {} failed: {error}", self.address))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tcp_endpoint_parses_into_its_host_and_port() {
        assert_eq!(
            parse_endpoint("tcp:server=10.0.0.5,port=5005").unwrap(),
            DbgsrvEndpoint::Tcp {
                server: "10.0.0.5".into(),
                port: 5005
            }
        );
        assert_eq!(
            parse_endpoint("tcp:port=5005,server=debug-host").unwrap(),
            DbgsrvEndpoint::Tcp {
                server: "debug-host".into(),
                port: 5005
            }
        );
        assert_eq!(
            parse_endpoint("tcp:server=127.0.0.1,port=5005")
                .unwrap()
                .to_string(),
            "tcp:server=127.0.0.1,port=5005"
        );
    }

    #[test]
    fn secure_transports_passwords_and_bad_ports_are_refused() {
        for endpoint in [
            "ssl:server=host,port=5005",
            "spipe:server=host,port=5005",
            "tcp:server=host,port=5005,password=secret",
            "npipe:server=host,port=5005",
            "1394:channel=1",
            "tcp:server=host,port=not-a-port",
            "tcp:server=host,port=70000",
            "tcp:port=5005",
            "tcp:server=host",
            "tcp:server=host,prot=5005",
            "tcp:server=host,port",
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
            parse_endpoint("tcp:server=host,port=5005,password=secret")
                .unwrap_err()
                .to_string()
                .contains("not supported")
        );
    }
}
