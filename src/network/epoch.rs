use std::future::Future;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use super::session::{ConsumerNetworkSession, NetworkSessionRuntime};
use crate::shutdown::combine_results;

/// Owns one transport epoch and lets its frontend restore local resources before closing the wire.
pub(crate) async fn run_network_epoch<F, S>(
    session: ConsumerNetworkSession,
    mut runtime: NetworkSessionRuntime,
    shutdown: CancellationToken,
    service: F,
) -> Result<()>
where
    F: FnOnce(ConsumerNetworkSession, CancellationToken) -> S,
    S: Future<Output = Result<()>>,
{
    let epoch = shutdown.child_token();
    let mut frontend = Box::pin(service(session, epoch.clone()));
    let mut frontend_finished = false;
    let result = tokio::select! {
        biased;
        _ = shutdown.cancelled() => Ok(()),
        result = &mut frontend => { frontend_finished = true; result },
        result = runtime.wait() => result,
    };
    runtime.stop_keepalive();
    epoch.cancel();
    let frontend_cleanup = if frontend_finished {
        Ok(())
    } else {
        frontend.as_mut().await
    };
    // Dropping the completed future releases its final request handles before HTTP/2 drains.
    drop(frontend);
    let transport_cleanup = runtime.shutdown().await;
    combine_results(
        combine_results(result, frontend_cleanup, "frontend cleanup also failed"),
        transport_cleanup,
        "network transport cleanup also failed",
    )
}
