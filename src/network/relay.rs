use anyhow::Result;
use bytes::Bytes;
use h2::{Reason, RecvStream, SendStream};
use http::{Request, Response};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::session::{
    ConsumerNetworkSession, TCP_DESTINATION_OPEN_TIMEOUT, map_h2_error, reject_request,
    send_h2_data, send_h2_end_stream, tcp_open_timeout_error,
};

/// Carries an existing CONNECT stream over the approved upstream session.
pub(super) async fn forward_network_request(
    request: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    upstream: &ConsumerNetworkSession,
) -> Result<()> {
    let _permit = match upstream.acquire_flow_permit() {
        Ok(permit) => permit,
        Err(error) => return reject_request(respond, error),
    };
    let (parts, receive) = request.into_parts();
    let head = Request::from_parts(parts, ());
    let deadline = Instant::now() + TCP_DESTINATION_OPEN_TIMEOUT;
    let opened = tokio::select! {
        biased;
        reset = std::future::poll_fn(|cx| respond.poll_reset(cx)) => { reset?; return Ok(()); },
        result = tokio::time::timeout_at(deadline, upstream.open_request(head, false)) => result,
    };
    let (response, send) = match opened {
        Ok(Ok(opened)) => opened,
        Ok(Err(error)) => return reject_request(respond, error),
        Err(_) => return reject_request(respond, tcp_open_timeout_error()),
    };
    let mut upload = RelayWriter::new(send);
    let response = tokio::select! {
        biased;
        reset = std::future::poll_fn(|cx| respond.poll_reset(cx)) => { reset?; return Ok(()); },
        result = tokio::time::timeout_at(deadline, response) => match result {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => return reject_request(respond, map_h2_error(error)),
            Err(_) => return reject_request(respond, tcp_open_timeout_error()),
        },
    };
    let (parts, response_body) = response.into_parts();
    let send = respond.send_response(Response::from_parts(parts, ()), false)?;
    let mut download = RelayWriter::new(send);
    let cancellation = CancellationToken::new();
    let (up, down) = tokio::join!(
        forward_h2_body(receive, &mut upload, cancellation.clone()),
        forward_h2_body(response_body, &mut download, cancellation),
    );
    up.and(down)
}

struct RelayWriter {
    stream: SendStream<Bytes>,
    finished: bool,
}

impl RelayWriter {
    fn new(stream: SendStream<Bytes>) -> Self {
        Self {
            stream,
            finished: false,
        }
    }
}

impl Drop for RelayWriter {
    fn drop(&mut self) {
        // Cancellation must reach the next hop even when its request is waiting for a response.
        if !self.finished {
            self.stream.send_reset(Reason::CANCEL);
        }
    }
}

async fn forward_h2_body(
    mut receive: RecvStream,
    send: &mut RelayWriter,
    cancellation: CancellationToken,
) -> Result<()> {
    let result = async {
        loop {
            let frame = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                frame = receive.data() => frame,
            };
            let Some(frame) = frame else {
                break;
            };
            let frame = frame?;
            let length = frame.len();
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                result = send_h2_data(&mut send.stream, frame, false) => result?,
            }
            // Credit is released only after the next hop admits the bytes.
            receive.flow_control().release_capacity(length)?;
        }
        let trailers = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Ok(()),
            trailers = receive.trailers() => trailers?,
        };
        match trailers {
            Some(trailers) => send.stream.send_trailers(trailers)?,
            None => send_h2_end_stream(&mut send.stream)?,
        }
        send.finished = true;
        Ok(())
    }
    .await;
    if result.is_err() {
        cancellation.cancel();
    }
    result
}
