mod configuration;
mod device;
mod dns;
mod packet;
mod probe;
mod routes;
mod runtime;

use crate::NetworkPolicy;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;

use crate::network::ConsumerNetworkSession;
use crate::shutdown::combine_results;

pub(super) const VPN_MTU: u16 = 1_500;
pub(super) const DATA_PLANE_HEALTH_PORT: u16 = 49_152;
const NETWORK_RECONCILE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Retains address identity and DNS mappings while individual VPN transports are replaced.
pub struct ConsumerVpn {
    policy: NetworkPolicy,
    addresses: Option<VpnAddresses>,
}

struct VpnAddresses {
    network: configuration::VpnNetworkConfiguration,
    mappings: Arc<Mutex<dns::SyntheticAddressMap>>,
}

impl ConsumerVpn {
    pub fn new(policy: NetworkPolicy) -> Self {
        Self {
            policy,
            addresses: None,
        }
    }

    pub(crate) async fn run(
        &mut self,
        session: ConsumerNetworkSession,
        transport_local: SocketAddr,
        transport_peer: SocketAddr,
        shutdown: CancellationToken,
    ) -> Result<()> {
        if shutdown.is_cancelled() {
            return Ok(());
        }
        let policy = &self.policy;
        let transport_peer_ip = normalize_ip(transport_peer.ip());
        validate_transport_peer(policy, transport_peer_ip)?;
        let selection = match &self.addresses {
            Some(addresses) => routes::AddressSelection::Retained(addresses.network),
            None => routes::AddressSelection::Fresh(rand::random()),
        };
        let prepared_network = routes::prepare(policy, selection, transport_peer_ip)
            .context("failed to prepare collision-free VPN network settings")?;
        let network = prepared_network.network_configuration();
        if self.addresses.is_none() {
            self.addresses = Some(VpnAddresses {
                network,
                mappings: Arc::new(Mutex::new(runtime::synthetic_address_map(
                    network.synthetic,
                )?)),
            });
        }
        let mappings = Arc::clone(
            &self
                .addresses
                .as_ref()
                .expect("VPN address state has been selected")
                .mappings,
        );
        let mut tun = device::SystemTun::create(network).context(
        "failed to create the VPN interface; run bifrost access with administrator/root privileges",
    )?;
        let mut network_guard = prepared_network
            .install(&tun.name, tun.index, transport_local, transport_peer)
            .with_context(|| {
                format!(
                    "failed to configure VPN host-network state on interface {}",
                    tun.name
                )
            })?;
        let (tun_reader, tun_writer) = tun.split()?;
        let mut packet_runtime = runtime::VpnRuntime::start(
            tun_reader,
            tun_writer,
            session,
            network,
            policy.clone(),
            mappings,
        );
        let mut network_reconcile = tokio::time::interval(NETWORK_RECONCILE_INTERVAL);
        network_reconcile.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        network_reconcile.tick().await;

        let mut readiness = Box::pin(probe::verify_data_plane(network, policy));
        let mut ready = false;
        let operation_result = loop {
            tokio::select! {
                result = &mut readiness, if !ready => {
                    match result {
                        Ok(()) => {
                            ready = true;
                            if policy.is_unrestricted() {
                                println!("full-tunnel VPN active on interface {}", tun.name);
                            } else {
                                println!("selective VPN active on interface {}", tun.name);
                            }
                            println!("press Ctrl-C to disconnect and restore the original routes");
                        }
                        Err(error) => break Err(anyhow::Error::new(crate::reconnect::FatalSessionFailure(error))).context(
                            "VPN data plane did not become ready after host-network installation",
                        ),
                    }
                }
                result = packet_runtime.wait() => break result,
                _ = network_reconcile.tick() => {
                    if let Err(error) = network_guard.reconcile() {
                        break Err(error).context(
                            "failed to reconcile VPN network settings after a host network change",
                        );
                    }
                }
                _ = shutdown.cancelled() => break Ok(()),
            }
        };
        let packet_shutdown_result = packet_runtime.shutdown().await;
        let restore_result = network_guard.restore();

        let operation_result = combine_results(
            operation_result,
            packet_shutdown_result,
            "VPN packet runtime shutdown also failed",
        );
        match restore_result {
            Ok(()) => operation_result,
            Err(error) => {
                let failure = combine_results(
                    operation_result,
                    Err(error),
                    "VPN host-network restoration also failed",
                )
                .expect_err("host-network restoration failed");
                Err(crate::reconnect::FatalSessionFailure(failure).into())
            }
        }
    }
}

fn validate_transport_peer(policy: &NetworkPolicy, peer: IpAddr) -> Result<()> {
    if policy.contains_exact_ip(peer) {
        bail!(
            "VPN include CIDR selects the WebSocket transport peer {peer} exactly; use a broader CIDR or remove that host selector so Bifrost can keep its control connection on the physical network"
        );
    }
    Ok(())
}

fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

#[cfg(test)]
mod tests {
    use super::{NetworkPolicy, validate_transport_peer};

    #[test]
    fn exact_transport_peer_selector_is_rejected() {
        let policy =
            NetworkPolicy::new(vec!["203.0.113.8/32".parse().unwrap()], Vec::new()).unwrap();

        assert!(validate_transport_peer(&policy, "203.0.113.8".parse().unwrap()).is_err());
    }

    #[test]
    fn broader_transport_peer_selector_is_safe() {
        let policy =
            NetworkPolicy::new(vec!["203.0.113.0/24".parse().unwrap()], Vec::new()).unwrap();

        validate_transport_peer(&policy, "203.0.113.8".parse().unwrap()).unwrap();
    }
}
