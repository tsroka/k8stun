# k8stun - Kubernetes Userspace Network Tunnel

[![CI](https://github.com/tsroka/k8stun/actions/workflows/ci.yml/badge.svg)](https://github.com/tsroka/k8stun/actions/workflows/ci.yml)

A transparent network tunnel that connects your local machine directly to a Kubernetes cluster. Access internal Kubernetes services (like `http://my-service.default`) from your local browser or terminal as if your laptop were physically inside the cluster network.

## Features

- **Transparent Access**: Access Kubernetes services and pods using their internal DNS names
- **No /etc/hosts Modifications**: Works at the network layer (Layer 3), no messy host file edits
- **No Kernel Modules**: Operates entirely in userspace using a TUN device
- **Automatic Service Discovery**: Discovers and exposes services from specified namespaces
- **DNS Interception**: Automatically resolves Kubernetes service and pod names to virtual IPs
- **Direct Pod Access**: Connect to individual pods using Kubernetes pod DNS patterns
- **Bidirectional Streaming**: Full TCP support with proper connection handling

## How It Works

```
┌─────────────────────┐     ┌──────────────────────────────────┐     ┌─────────────┐
│   Your Terminal     │     │         k8stun Process           │     │ Kubernetes  │
│  curl app.default   │  →  │ TUN → lwIP stack → Port Forward  │  →  │    Pod      │
└─────────────────────┘     └──────────────────────────────────┘     └─────────────┘
```

1. **DNS Hijack**: When you access `backend.default` or `mysql-0.mysql.default`, the DNS query is intercepted
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
  -l, --log-level <LOG_LEVEL>    Log level (trace, debug, info, warn, error) [default: info]
      --mtu <MTU>                MTU for the TUN device [default: 1500]
      --idle-timeout <SECONDS>   Idle connection timeout in seconds (0 = no timeout) [default: 300]
      --dns-mode <MODE>          DNS interception mode [default: tun_route]
                                   - disabled: No DNS interception
                                   - tun_route: Route DNS traffic through TUN device
                                   - forward: Change system DNS settings (macOS only)
      --http <PORT>              Port for the HTTP API server (0 to disable) [default: 0]
  -c, --context <CONTEXT>        Kubernetes context to use (from kubeconfig)
  -h, --help                     Print help
  -V, --version                  Print version
```

### DNS Modes

k8stun supports three DNS interception modes:

| Mode | Description | Platform |
|------|-------------|----------|
| `tun_route` | Routes DNS traffic through the TUN device by adding a route to the system's DNS server. This is the default mode. | All |
| `forward` | Changes macOS system DNS settings to point to a DNS server running on the TUN interface. Original settings are restored on exit. | macOS only |
| `disabled` | No DNS interception. You must use VIP addresses directly. | All |

```bash
# Default mode - route DNS through TUN
sudo k8stun --dns-mode tun_route

# Forward mode on macOS - modify system DNS settings
sudo k8stun --dns-mode forward

# Disable DNS interception entirely
sudo k8stun --dns-mode disabled
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
# Access services by name
$ curl http://backend.default/api/health
{"status": "ok"}

$ curl http://api.production:8080/users
[{"id": 1, "name": "Alice"}, ...]

# Access individual pods directly (StatefulSet)
$ curl http://mysql-0.mysql.default:3306/
$ curl http://redis-0.redis.cache:6379/

# Access pods by IP
$ curl http://172-17-0-3.default.pod:8080/
```

## Supported DNS Patterns

k8stun supports the standard Kubernetes DNS naming conventions:

### Service DNS

```bash
# Short form (requires namespace to be known)
curl http://my-service.default/

# Full form
curl http://my-service.default.svc.cluster.local/
```

### Pod DNS

Connect directly to individual pods using Kubernetes pod DNS patterns:

```bash
# StatefulSet pods (pod-name.service-name.namespace)
curl http://mysql-0.mysql.default/
curl http://redis-0.redis.cache.svc.cluster.local/

# Pod by IP address (ip-with-dashes.namespace.pod)
curl http://172-17-0-3.default.pod.cluster.local/
curl http://10-0-0-5.production.pod/
```

This is particularly useful for:
- Connecting to specific replicas of a StatefulSet (e.g., MySQL primary vs replica)
- Debugging individual pods
- Testing pod-to-pod communication patterns

## HTTP API

k8stun can optionally expose an HTTP API for monitoring VIP allocations and connections. Enable it with `--http <port>`:

```bash
sudo k8stun --http 8080
```

### Endpoints

#### GET /vips

Returns a JSON snapshot of all current VIP mappings:

```bash
curl http://localhost:8080/vips
```

```json
{
  "vips": [
    {
      "vip": "198.18.0.2",
      "target": { "type": "service", "name": "backend", "namespace": "default" },
      "stats": {
        "active_connections": 2,
        "total_connections": 15,
        "bytes_sent": 12345,
        "bytes_received": 67890
      }
    }
  ]
}
```

#### GET /events

Server-Sent Events (SSE) endpoint for real-time updates. The first message is a snapshot of all VIPs, followed by delta updates as changes occur:

```bash
curl http://localhost:8080/events
```

Events include:
- `snapshot` - Initial state with all VIPs
- `vip_allocated` - A new VIP was assigned
- `vip_removed` - A VIP was deallocated (stale cleanup)
- `connection_changed` - Connection count changed

## Requirements

- Rust 1.70+ (for building)
- macOS or Linux
- Kubernetes cluster with valid kubeconfig
- Root/sudo privileges

## Architecture

```
src/
├── main.rs              - Entry point, CLI, orchestration
├── tun.rs               - TUN device creation and OS routing
├── vip.rs               - Virtual IP pool management (services & pods)
├── dns.rs               - DNS packet parsing for services and pods
├── dns_resolver.rs      - DNS resolution with upstream forwarding
├── dns_intercept.rs     - DNS interception via TUN routing
├── dns_forward_macos.rs - macOS system DNS settings (forward mode)
├── stack.rs             - Userspace TCP/IP stack (lwIP/smoltcp)
├── k8s.rs               - Kubernetes client, pod lookup, and port-forwarding
├── pipe.rs              - Bidirectional stream copying
└── api/                 - HTTP API server (optional)
    ├── mod.rs           - Server setup and routing
    ├── handlers.rs      - Route handlers (GET /vips, SSE /events)
    └── types.rs         - API response types
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tun2` | Cross-platform TUN device management |
| `netstack-smoltcp` | Userspace TCP/IP stack (default) |
| `lwip` | Alternative userspace TCP/IP stack |
| `kube` | Kubernetes API client |
| `k8s-openapi` | Kubernetes API types |
| `tokio` | Async runtime |
| `clap` | CLI argument parsing |
| `tracing` | Structured logging |
| `hickory-proto` | DNS protocol handling |
| `hickory-resolver` | DNS resolution and forwarding |
| `etherparse` | Network packet parsing |
| `system-configuration` | macOS system DNS settings (forward mode) |

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

