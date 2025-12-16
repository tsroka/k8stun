//! Network stack module with pluggable implementations.
//!
//! This module provides a userspace TCP/IP stack that can use different backends:
//! - `stack-lwip` (default): Uses the lwIP stack
//! - `stack-smoltcp`: Uses the smoltcp stack via netstack-smoltcp

#[cfg(all(feature = "stack-lwip", feature = "stack-smoltcp"))]
compile_error!("Features 'stack-lwip' and 'stack-smoltcp' cannot be enabled simultaneously.");

#[cfg(not(any(feature = "stack-lwip", feature = "stack-smoltcp")))]
compile_error!("One of 'stack-lwip' or 'stack-smoltcp' features must be enabled.");

mod common;
pub use common::UdpPacket;

#[cfg(feature = "stack-lwip")]
mod lwip;
#[cfg(feature = "stack-lwip")]
#[allow(unused_imports)]
pub use lwip::{AcceptedConnection, NetworkStack, TcpStream};

#[cfg(feature = "stack-smoltcp")]
mod smoltcp;
#[cfg(feature = "stack-smoltcp")]
#[allow(unused_imports)]
pub use smoltcp::{AcceptedConnection, NetworkStack, TcpStream};
