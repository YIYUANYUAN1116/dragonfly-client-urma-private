//! URMA READ capability discovery over the normal TCP Piece endpoint.
use crate::rendezvous::ERROR_CODE_INCOMPATIBLE;
use crate::urma::rendezvous::{read_frame, write_frame, Frame, UrmaAdvertisement};
use dragonfly_client_core::{Error as ClientError, Result as ClientResult};
use socket2::{SockRef, TcpKeepalive};
use std::time::Duration;
use tokio::{net::TcpStream, time};
use tracing::{instrument, Span};

/// discover asks the parent's already-advertised TCP piece endpoint for its live
/// URMA capability and rendezvous port. Non-URMA peers simply fail this optional
/// probe, leaving the downloader to fall back to the TCP piece transport.
#[instrument(skip_all, fields(parent_addr))]
pub async fn discover(addr: &str, timeout: Duration) -> ClientResult<UrmaAdvertisement> {
    Span::current().record("parent_addr", addr);
    time::timeout(timeout, async {
        let stream = TcpStream::connect(addr).await?;
        let socket = SockRef::from(&stream);
        socket.set_tcp_nodelay(true)?;
        socket.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_interval(super::DEFAULT_KEEPALIVE_INTERVAL)
                .with_time(super::DEFAULT_KEEPALIVE_TIME)
                .with_retries(super::DEFAULT_KEEPALIVE_RETRIES),
        )?;
        let (mut reader, mut writer) = stream.into_split();
        write_frame(&mut writer, &Frame::Discover).await?;
        match read_frame(&mut reader).await? {
            Frame::Capability(advertisement) if advertisement.port != 0 => Ok(advertisement),
            Frame::Capability(_) => Err(ClientError::Unsupported(
                "parent advertised an invalid urma rendezvous port".to_string(),
            )),
            Frame::Error { error: err, .. } if err.code == ERROR_CODE_INCOMPATIBLE => {
                Err(ClientError::Unsupported(err.message))
            }
            Frame::Error { error: err, .. } => Err(ClientError::Unknown(format!(
                "urma discovery error {}: {}",
                err.code, err.message
            ))),
            frame => Err(ClientError::Unknown(format!(
                "unexpected urma discovery frame: {frame:?}"
            ))),
        }
    })
    .await?
}
