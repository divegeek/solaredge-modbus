use std::borrow::Cow;
use std::collections::HashSet;
use std::net::IpAddr;
use std::pin::pin;

use async_timer::{Expired, Timed};
use log::{error, trace};
use mdns_sd::{ServiceDaemon, ServiceEvent};

use crate::Error;

pub const SOLAREDGE_INVERTER_SERVICE_TYPE: &str = "_solaredge-modbus._tcp.local.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolaredgeHostInfo {
	pub hostname: String,
	pub addresses: HashSet<IpAddr>,
	pub port: u16,
	pub modbus_id: u8,
}

impl SolaredgeHostInfo {
	/// Returns the first IP address if available or hostname otherwise.
	pub fn address(&self) -> Cow<'_, str> {
		self
			.addresses
			.iter()
			.next()
			.map_or_else(|| Cow::Borrowed(self.hostname.as_str()), |ip| Cow::Owned(ip.to_string()))
	}
}

/// Perform mDNS discovery and return the Solaredge Inverters found on the local network.
///
/// Due to the unpredictable nature of mDNS, you need to supply the `timeout` argument to specify how long should the call wait
/// for the DNS results. If you know how many inverters there are on the LAN, specify that value in `max_hosts` so that the function
/// returns as soon as the requested count is reached. Otherwise, specify `0` or [usize::MAX] to collect as many as possible
/// within the specified interval.
///
/// It is also possible that this call doesn't return any results even if inverters are available. For more robustness it's
/// recommended to check the result of the call and retry a couple of times if it's empty.
pub async fn discover_with_mdns(timeout: std::time::Duration, max_hosts: usize) -> Result<Vec<SolaredgeHostInfo>, Error> {
	let max_hosts = if max_hosts == 0 {
		usize::MAX
	} else {
		max_hosts
	};
	let mdns = ServiceDaemon::new()?;
	let receiver = mdns.browse(SOLAREDGE_INVERTER_SERVICE_TYPE)?;
	let mut out = Vec::with_capacity(1);
	{
		let discover = async {
			while let Ok(event) = receiver.recv_async().await {
				if let ServiceEvent::ServiceResolved(info) = event {
					let modbus_id = info.get_property_val_str("MODBUS_ID");
					if let Some(modbus_id) = modbus_id.and_then(|s| s.parse::<u8>().ok()) {
						out.push(SolaredgeHostInfo {
							hostname: info.host,
							addresses: info.addresses.into_iter().map(|addr| addr.to_ip_addr()).collect(),
							port: info.port,
							modbus_id,
						});
						if out.len() >= max_hosts {
							break;
						}
					} else {
						error!("Failed to find or parse modbus ID: {modbus_id:?}");
					}
				}
			}
		};
		let discover = pin!(discover);
		match Timed::platform_new(discover, timeout).await {
			Ok(()) => {}
			Err(Expired { .. }) => trace!("mDNS Discovery timed out"),
		}
	}
	trace!("Found {} host(s) via mDNS Discovery", out.len());
	mdns.shutdown()?;
	Ok(out)
}
