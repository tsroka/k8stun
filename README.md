# k8stun - Kubernetes Userspace Network Tunnel

[![CI](https://github.com/tsroka/k8stun/actions/workflows/ci.yml/badge.svg)](https://github.com/tsroka/k8stun/actions/workflows/ci.yml)

A transparent network tunnel that connects your local machine directly to a Kubernetes cluster. Access internal Kubernetes services (like `http://my-service.default`) from your local browser or terminal as if your laptop were physically inside the cluster network.

## Features

- **Transparent Access**: Access Kubernetes services using their internal DNS names
- **No /etc/hosts Modifications**: Works at the network layer (Layer 3), no messy host file edits
- **No Kernel Modules**: Operates entirely in userspace using a TUN device
- **Automatic Service Discovery**: Discovers and exposes services from specified namespaces
- **DNS Interception**: Automatically resolves Kubernetes service names to virtual IPs
- **Bidirectional Streaming**: Full TCP support with proper connection handling

## How It Works

```
┌─────────────────────┐     ┌──────────────────────────────────┐     ┌─────────────┐
│   Your Terminal     │     │         k8stun Process           │     │ Kubernetes  │
│  curl backend.default │ → │ TUN → lwIP stack → Port Forward │ → │    Pod      │
└─────────────────────┘     └──────────────────────────────────┘     └─────────────┘
```

1. **DNS Hijack**: When you access `backend.default`, the DNS query is intercepted
2. **VIP Allocation**: A virtual IP (e.g., `198.18.0.5`) is assigned and returned
3. **Routing**: Traffic to the VIP range is captured by the TUN device
4. **Userspace TCP**: The `lwip` library terminates TCP connections in userspace
5. **Port Forward**: Connections are forwarded to Kubernetes pods via the API

## Installation

### macOS (Homebrew)

```bash
brew install tsroka/k8stun/k8stun
```

### Debian/Ubuntu

Download the latest `.deb` package from the [releases page](https://github.com/tsroka/k8stun/releases):

```bash
# For x64
curl -LO https://github.com/tsroka/k8stun/releases/latest/download/k8stun_VERSION_amd64.deb
sudo dpkg -i k8stun_VERSION_amd64.deb

# For ARM64
curl -LO https://github.com/tsroka/k8stun/releases/latest/download/k8stun_VERSION_arm64.deb
sudo dpkg -i k8stun_VERSION_arm64.deb
```

### From Source

```bash
# Clone the repository
git clone https://github.com/tsroka/k8stun.git
cd k8stun

# Build the project
cargo build --release

# The binary will be at target/release/k8stun
```

## Usage

**Note**: Requires root/sudo privileges for TUN device creation and routing.

```bash
# Basic usage - expose services in the default namespace
sudo ./target/release/k8stun

# Expose services from multiple namespaces
sudo ./target/release/k8stun --namespaces default,production,staging

# Specify individual services
sudo ./target/release/k8stun --services backend.default:8080,api.production:3000

# Enable debug logging
sudo ./target/release/k8stun --log-level debug
```

### CLI Options

```
Options:
  -n, --namespaces <NAMESPACES>  Kubernetes namespaces to expose (comma-separated) [default: default]
      --vip-base <VIP_BASE>      Virtual IP range base (e.g., 198.18.0.0) [default: 198.18.0.0]
      --auto-discover <BOOL>     Pre-allocate VIPs for all discovered services [default: true]
  -s, --services <SERVICES>      Specific services to expose (format: service.namespace:port)
  -l, --log-level <LOG_LEVEL>    Log level (trace, debug, info, warn, error) [default: info]
      --mtu <MTU>                MTU for the TUN device [default: 1500]
      --idle-timeout <SECONDS>   Idle connection timeout in seconds (0 = no timeout) [default: 300]
  -h, --help                     Print help
  -V, --version                  Print version
```

## Example Session

```bash
$ sudo ./target/release/k8stun --namespaces default,production

Starting k8stun - Kubernetes Userspace Network Tunnel
Target namespaces: ["default", "production"]
Connecting to Kubernetes cluster...
Discovering services in target namespaces...
  198.18.0.2 -> backend.default:80 (port 80)
  198.18.0.3 -> frontend.default:3000 (port 3000)
  198.18.0.4 -> api.production:8080 (port 8080)

TUN device created: utun5
Network stack initialized

===========================================
k8stun is ready!
===========================================

You can now access Kubernetes services:
  curl http://198.18.0.2:80/
    -> backend.default
  curl http://198.18.0.3:3000/
    -> frontend.default
  curl http://198.18.0.4:8080/
    -> api.production

Press Ctrl+C to stop.
```

In another terminal:
```bash
$ curl http://backend.default/api/health
{"status": "ok"}

$ curl http://api.production:8080/users
[{"id": 1, "name": "Alice"}, ...]
```

## Requirements

- Rust 1.70+ (for building)
- macOS or Linux
- Kubernetes cluster with valid kubeconfig
- Root/sudo privileges

## Architecture

```
src/
├── main.rs          - Entry point, CLI, orchestration
├── tun.rs           - TUN device creation and OS routing
├── vip.rs           - Virtual IP pool management
├── dns.rs           - DNS packet parsing and response building
├── dns_intercept.rs - DNS query interception and resolution
├── stack.rs         - Userspace TCP/IP stack (lwIP)
├── k8s.rs           - Kubernetes client and port-forwarding
└── pipe.rs          - Bidirectional stream copying
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tun2` | Cross-platform TUN device management |
| `lwip` | Userspace TCP/IP stack (lwIP-based) |
| `kube` | Kubernetes API client |
| `k8s-openapi` | Kubernetes API types |
| `tokio` | Async runtime |
| `clap` | CLI argument parsing |
| `tracing` | Structured logging |
| `hickory-proto` | DNS protocol handling |
| `etherparse` | Network packet parsing |

## Limitations

- TCP only 
- IPv4 only
- Requires root privileges
- Single cluster at a time

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

