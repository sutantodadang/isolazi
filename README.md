# isolazi

A minimal container runtime written in Zig, inspired by Docker, Podman, and OCI runtimes (runc, crun, youki).

## Features

- 🐳 **Docker-like CLI** - Familiar commands: `run`, `pull`, `ps`, `stop`, `rm`, `exec`
- 📦 **OCI Image Support** - Pull images from Docker Hub and other registries
- 🔒 **Process Isolation** - Linux namespaces (PID, mount, UTS, IPC, **network**, **user**, **cgroup**)
- 🛡️ **Seccomp Filtering** - Block dangerous syscalls with configurable profiles
- 🔐 **AppArmor/SELinux** - Mandatory Access Control for defense-in-depth security
- 🌐 **Network Isolation** - veth pairs, bridge networking, NAT, and port forwarding
- 👤 **Rootless Containers** - User namespace support for unprivileged container execution
- ⚙️ **Resource Limits** - cgroup v2 support for memory, CPU, and I/O limits
- 🗂️ **Filesystem Isolation** - Using `pivot_root` or `chroot`
- 🔧 **Exec into Containers** - Execute commands in running containers using `nsenter`
- 🪟 **Windows Support** - Run containers via WSL2 backend
- 🍎 **macOS Support** - Run containers via Apple Virtualization framework
- ⚡ **Fast & Lightweight** - Written in Zig with minimal dependencies

## Current Status (January 26, 2026)

- ✅ **Core commands**: `run`, `build`, `pull`, `images`, `ps`, `create`, `start`, `stop`, `rm`, `exec`, `logs`, `prune`, `update`
- ✅ **Image Builder**: Build images from Isolazifile/Dockerfile (`FROM`, `RUN`, `COPY`, `ADD`, `ENV`, `WORKDIR`, `ARG`, `CMD`, `ENTRYPOINT`)
- ✅ **Prune behavior**: `prune` removes stopped containers and unused images; `prune -f/--force` removes all containers
- ✅ **Rootless mode**: `--rootless` with optional `--uid-map`/`--gid-map`
- ✅ **Networking**: bridge + veth, NAT, port publishing (`-p`)
- ✅ **Security**: seccomp filtering, AppArmor/SELinux toggles, user namespaces
- ✅ **Resource limits**: cgroup v2 memory/CPU/I/O/OOM controls
- ✅ **Platforms**: Linux (native), Windows (WSL2), macOS (Linux VM via Lima/vfkit)
- ✅ **Cross-builds**: targets validated for `x86_64-windows`, `x86_64-linux`, `x86_64-macos`, `aarch64-macos`

## Installation

### Quick Install (Recommended)

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/sutantodadang/isolazi/main/install.sh | bash
```

Or clone and run locally:
```bash
git clone https://github.com/sutantodadang/isolazi.git
cd isolazi
./install.sh
```

**Windows (PowerShell as Administrator):**
```powershell
irm https://raw.githubusercontent.com/sutantodadang/isolazi/main/install.ps1 | iex
```

Or clone and run locally:
```powershell
git clone https://github.com/sutantodadang/isolazi.git
cd isolazi
.\install.ps1
```

The installer will:
- ✅ Download pre-built binary from GitHub releases
- ✅ Auto-detect your platform (macOS/Linux, x86_64/arm64)
- ✅ Install the binary to `~/.isolazi/bin`
- ✅ Add to your PATH (supports zsh, bash, fish, PowerShell)

**Install specific version:**
```bash
# macOS / Linux
ISOLAZI_VERSION=v0.1.11 curl -fsSL https://raw.githubusercontent.com/sutantodadang/isolazi/main/install.sh | bash

# Windows
.\install.ps1 -Version v0.1.11
```

**Uninstall:**
```bash
# macOS / Linux
./install.sh --uninstall

# Windows
.\install.ps1 -Uninstall
```

### Prerequisites

- [Zig](https://ziglang.org/download/) 0.15.2 or later (auto-installed by script)
- Linux kernel with namespace support (for native execution)
- WSL2 (for Windows)
- macOS 12.0+ with Lima (for macOS)

### Manual Build from Source

```bash
git clone https://github.com/sutantodadang/isolazi.git
cd isolazi
zig build -Doptimize=ReleaseFast
```

The binary will be available at `zig-out/bin/isolazi`.

To manually add to PATH:
```bash
# Bash
echo 'export PATH="$PATH:$HOME/.isolazi/bin"' >> ~/.bashrc

# Zsh
echo 'export PATH="$PATH:$HOME/.isolazi/bin"' >> ~/.zshrc

# Fish
echo 'set -gx PATH $PATH $HOME/.isolazi/bin' >> ~/.config/fish/config.fish
```

## Quick Start

### Pull an Image

```bash
isolazi pull alpine:latest
```

### Build an Image

Create an `Isolazifile` (or `Dockerfile`):
```dockerfile
FROM alpine:latest
RUN echo "Hello from Isolazi Build" > /message.txt
CMD cat /message.txt
```

Build the image:
```bash
isolazi build -t my-image:v1 .
```

The image will be available locally:
```bash
isolazi images
```

See [docs/BUILD.md](docs/BUILD.md) for full documentation on supported instructions and options.

### Run a Container

```bash
# Interactive shell
isolazi run alpine /bin/sh

# Run a command
isolazi run alpine echo "Hello from container!"

# Run in detached mode
isolazi run -d alpine sleep 300

# With environment variables
isolazi run -e MYVAR=hello -e DEBUG=1 alpine env

# With volume mounts
isolazi run -v /host/data:/container/data alpine ls /container/data

# With port publishing (network namespace enabled by default)
isolazi run -d -p 8080:80 nginx

# Multiple port mappings
isolazi run -d -p 8080:80 -p 8443:443 nginx

# UDP port mapping
isolazi run -d -p 5353:53/udp coredns

# Run PostgreSQL with all options
isolazi run -d -p 5432:5432 \
  -e POSTGRES_PASSWORD=secret,POSTGRES_USER=myuser,POSTGRES_DB=mydb \
  -v /mydata:/var/lib/postgresql/data \
  postgres:16-alpine

# Rootless containers (no root required)
isolazi run --rootless alpine /bin/sh

# Rootless with custom UID/GID mapping
isolazi run --rootless --uid-map 0:1000:1 --gid-map 0:1000:1 alpine /bin/sh

# With resource limits (cgroup v2)
isolazi run --memory 512m --cpus 2 alpine /bin/sh

# Memory limits
isolazi run -m 256m alpine stress --vm 1 --vm-bytes 128M

# CPU limits (quota-based)
isolazi run --cpus 1.5 alpine /bin/sh          # 1.5 CPU cores
isolazi run --cpu-quota 50000 alpine /bin/sh   # 50% of one CPU

# CPU weight (relative priority)
isolazi run --cpu-weight 512 alpine /bin/sh    # Lower priority (default: 100)

# I/O weight
isolazi run --io-weight 50 alpine dd if=/dev/zero of=/tmp/test bs=1M count=100

# OOM configuration
isolazi run --oom-score-adj 500 alpine /bin/sh       # More likely to be killed
isolazi run --oom-kill-disable alpine /bin/sh        # Disable OOM killer

# Combine resource limits
isolazi run -d -m 1g --cpus 2 --io-weight 100 -p 8080:80 nginx

# With seccomp filtering (default: blocks dangerous syscalls)
isolazi run alpine /bin/sh

# Use minimal seccomp profile for more permissive filtering
isolazi run --seccomp minimal alpine /bin/sh

# Strict seccomp profile (allowlist mode)
isolazi run --seccomp strict alpine /bin/sh

# Disable seccomp (for debugging only - NOT recommended)
isolazi run --no-seccomp alpine /bin/sh
```

### Container Management

```bash
# List running containers
isolazi ps

# List all containers (including stopped)
isolazi ps -a

# Create a container without starting
isolazi create --name myapp alpine

# Start a stopped container
isolazi start myapp

# Stop a running container
isolazi stop myapp

# Remove a container
isolazi rm myapp

# Force remove a running container
isolazi rm -f myapp

# Inspect container details
isolazi inspect myapp

# Clean up stopped containers and unused images
isolazi prune

# Force remove all containers and unused images
isolazi prune -f
```

### Update Isolazi

```bash
# Update to the latest version
isolazi update
```

### Container Logs

```bash
# View container logs (stdout and stderr)
isolazi logs <container_id>

# Follow log output (like tail -f)
isolazi logs -f <container_id>

# Show last N lines
isolazi logs --tail 100 <container_id>
isolazi logs -n 50 <container_id>

# Show timestamps
isolazi logs -t <container_id>
isolazi logs --timestamps <container_id>

# Show only stdout or stderr
isolazi logs --stdout <container_id>
isolazi logs --stderr <container_id>

# Combine options
isolazi logs -f --tail 20 -t <container_id>
```

### Execute Commands in Running Containers

```bash
# Run an interactive shell in a running container
isolazi exec -it <container_id> /bin/sh

# Run a command in a running container
isolazi exec <container_id> ls -la /

# Run command with environment variables
isolazi exec -e MYVAR=value <container_id> env

# Run command as a different user
isolazi exec -u nobody <container_id> id

# Run command in a specific working directory
isolazi exec -w /tmp <container_id> pwd

# Run command in background (detached)
isolazi exec -d <container_id> sleep 100
```

### Image Management

```bash
# List cached images
isolazi images

# Pull from different registries
isolazi pull docker.io/library/nginx:latest
isolazi pull ghcr.io/owner/repo:tag
```

## Usage

```
isolazi <COMMAND> [OPTIONS]

COMMANDS:
    run [-d] <image> [command]       Run a command in a new container
    build [OPTIONS] <path>           Build an image from an Isolazifile
    exec [OPTIONS] <container> <cmd> Execute a command in a running container
    logs [-f] <container>            Display container logs
    create [--name NAME] <image>     Create a container without starting
    start <container>                Start a stopped container
    stop <container>                 Stop a running container
    rm [-f] <container>              Remove a container
    ps [-a]                          List containers
    inspect <container>              Display container details
    pull <image>                     Pull an image from a registry
    images                           List cached images
    prune [-f]                       Remove stopped containers and unused images
    update                           Update isolazi to the latest version
    version                          Print version information
    help                             Print this help message

OPTIONS for 'build':
    -f, --file <path>         Name of the Isolazifile (default: 'Isolazifile')
    -t, --tag <name>          Name and optionally a tag in the 'name:tag' format
    --build-arg <arg>         Set build-time variables
    --no-cache                Do not use cache when building the image
    -q, --quiet               Suppress the build output and print image ID on success

OPTIONS for 'run':
    -d, --detach              Run container in background
    -e, --env KEY=VALUE       Set environment variable (comma-separated: KEY1=V1,KEY2=V2)
    -v, --volume SRC:DST[:ro] Mount a volume (can be repeated)
    -p, --port HOST:CONTAINER Publish container port to host (can be repeated)
    --hostname <name>         Set the container hostname
    --cwd <path>              Set the working directory
    --rootless                Run container without root privileges (user namespace)
    --uid-map C:H:S           Map container UID C to host UID H for S IDs
    --gid-map C:H:S           Map container GID C to host GID H for S IDs
    
    Resource Limits (cgroup v2):
    -m, --memory <size>       Memory limit (e.g., 512m, 1g, 1073741824)
    --memory-swap <size>      Swap limit (memory + swap)
    -c, --cpus <num>          CPU cores limit (e.g., 2, 0.5, 1.5)
    --cpu-quota <usec>        CPU quota in microseconds per period
    --cpu-period <usec>       CPU period (default: 100000)
    --cpu-weight <1-10000>    CPU weight for scheduling (default: 100)
    --io-weight <1-10000>     Block I/O weight (default: 100)
    --oom-score-adj <-1000..1000>  OOM killer score adjustment
    --oom-kill-disable        Disable OOM killer for this container

    Security Options:
    --seccomp <profile>       Seccomp profile: default, minimal, strict, disabled
    --no-seccomp              Disable seccomp filtering (less secure)
    --apparmor [profile]      Enable AppArmor with optional profile (default: isolazi-default)
    --apparmor-mode <mode>    AppArmor mode: enforce, complain, unconfined
    --no-apparmor             Disable AppArmor restrictions
    --selinux [context]       Enable SELinux with optional context
    --selinux-type <type>     SELinux type: container_t, container_net_t, container_file_t, spc_t
    --selinux-mcs <cats>      SELinux MCS categories (e.g., c1,c2)
    --no-selinux              Disable SELinux labeling
    --security-opt <opt>      Security option (Docker-compatible): apparmor=profile, label=context
    --privileged              Disable all security features (NOT recommended)

OPTIONS for 'exec':
    -i, --interactive         Keep STDIN open
    -t, --tty                 Allocate a pseudo-TTY
    -d, --detach              Run command in background
    -e, --env KEY=VALUE       Set environment variable
    -u, --user <user>         Run command as specified user
    -w, --workdir <path>      Working directory inside the container

OPTIONS for 'logs':
    -f, --follow              Follow log output (stream new logs)
    -n, --tail <N>            Show last N lines
    -t, --timestamps          Show timestamps with each line
    --stdout                  Show only stdout logs
    --stderr                  Show only stderr logs

OPTIONS for 'ps':
    -a, --all            Show all containers (default: only running)

OPTIONS for 'rm':
    -f, --force          Force remove running container

OPTIONS for 'prune':
    -f, --force          Remove all containers (including running)
```

## Image References

isolazi supports standard OCI image references:

| Format | Example | Description |
|--------|---------|-------------|
| Short name | `alpine` | Defaults to `docker.io/library/alpine:latest` |
| With tag | `alpine:3.18` | Specific version |
| Full reference | `docker.io/library/alpine:3.18` | Complete path |
| Other registries | `ghcr.io/owner/repo:tag` | GitHub Container Registry |

## Architecture

```
isolazi/
├── src/
│   ├── main.zig          # CLI entry point
│   ├── root.zig          # Module exports
│   ├── cli/              # Command-line interface
│   ├── config/           # Container configuration
│   ├── container/        # Container state management
│   ├── image/            # OCI image handling
│   │   ├── cache.zig     # Local image cache
│   │   ├── layer.zig     # Layer extraction
│   │   ├── reference.zig # Image reference parsing
│   │   └── registry.zig  # Registry client
│   ├── runtime/          # Container runtime (Linux)
│   │   └── container.zig # Container execution and exec support
│   ├── linux/            # Linux-specific (namespaces, networking, security)
│   │   ├── syscalls.zig  # Low-level Linux syscall wrappers (setns, nsenter)
│   │   ├── network.zig   # Container networking (veth, bridge, NAT)
│   │   ├── userns.zig    # User namespace for rootless containers
│   │   ├── cgroup.zig    # cgroup v2 resource limits
│   │   ├── seccomp.zig   # Seccomp syscall filtering
│   │   ├── apparmor.zig  # AppArmor MAC profile management
│   │   └── selinux.zig   # SELinux context and labeling
│   ├── fs/               # Filesystem operations
│   ├── windows/          # WSL2 backend (LSM passthrough)
│   └── macos/            # Lima VM backend (LSM passthrough)
├── build.zig
└── build.zig.zon
```

## Security

### Seccomp Syscall Filtering

Isolazi uses seccomp-bpf to restrict syscalls available inside containers. This provides defense-in-depth against container escapes and privilege escalation.

**Seccomp Profiles:**

| Profile | Description | Use Case |
|---------|-------------|----------|
| `default` | Blocks dangerous syscalls (default) | Production containers |
| `minimal` | Only blocks critical syscalls | When you need more syscalls |
| `strict` | Allowlist mode - minimal syscalls | High-security environments |
| `disabled` | No filtering | Debugging only |

**Default Profile Blocked Syscalls:**
- `mount`, `umount` - Filesystem manipulation
- `ptrace` - Process tracing/debugging
- `kexec_load`, `kexec_file_load` - Kernel replacement
- `reboot` - System reboot
- `init_module`, `delete_module` - Kernel modules
- `settimeofday`, `clock_settime` - Time manipulation
- `sethostname`, `setdomainname` - Hostname changes
- `pivot_root` - Root filesystem changes
- `bpf`, `perf_event_open` - Kernel debugging
- `setns`, `unshare` - Namespace manipulation
- `open_by_handle_at` - Filesystem escape vector

**Usage Examples:**

```bash
# Default security (recommended)
isolazi run alpine /bin/sh

# Minimal profile for applications that need more syscalls
isolazi run --seccomp minimal alpine /bin/sh

# Strict profile for high-security environments
isolazi run --seccomp strict alpine /bin/sh

# Disable seccomp for debugging (NOT recommended for production)
isolazi run --no-seccomp alpine /bin/sh
```

**How it Works:**
1. BPF filter is generated from the selected profile
2. `prctl(PR_SET_NO_NEW_PRIVS)` is set to enable unprivileged seccomp
3. Filter is installed via `seccomp(SECCOMP_SET_MODE_FILTER)`
4. Container process and all children are restricted

### AppArmor (Linux Security Module)

AppArmor provides Mandatory Access Control (MAC) to restrict what a container can do. It's particularly effective at preventing file access and capability-based attacks.

**AppArmor Modes:**

| Mode | Description | Use Case |
|------|-------------|----------|
| `enforce` | Actively blocks policy violations (default) | Production containers |
| `complain` | Logs violations without blocking | Testing and debugging |
| `unconfined` | No restrictions | When AppArmor isn't needed |

**Default Profile Restrictions:**
- Blocks access to `/proc/kcore`, `/proc/kmem`, `/proc/sysrq-trigger`
- Blocks `/sys/firmware/**` to prevent firmware tampering
- Blocks container runtime sockets (`/var/run/docker.sock`, etc.)
- Denies `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`
- Denies raw network access and kernel keyring access

**Usage Examples:**

```bash
# Enable AppArmor with default profile
isolazi run --apparmor alpine /bin/sh

# Use a custom AppArmor profile
isolazi run --apparmor my-profile alpine /bin/sh

# AppArmor in complain mode (log only)
isolazi run --apparmor --apparmor-mode complain alpine /bin/sh

# Disable AppArmor
isolazi run --no-apparmor alpine /bin/sh

# Docker-compatible security option
isolazi run --security-opt apparmor=my-profile alpine /bin/sh
```

**Platform Support:**
- **Linux**: Native AppArmor support (requires AppArmor enabled in kernel)
- **Windows (WSL2)**: Passed through to Linux isolazi inside WSL
- **macOS (Lima)**: Passed through to Linux VM (if AppArmor is available)

### SELinux (Security-Enhanced Linux)

SELinux provides Type Enforcement (TE) and Multi-Category Security (MCS) for fine-grained access control between containers.

**SELinux Types:**

| Type | Description | Use Case |
|------|-------------|----------|
| `container_t` | Standard container type (default) | Most containers |
| `container_net_t` | Container with network access | Network services |
| `container_file_t` | Container with file access | Data processing |
| `spc_t` | Super Privileged Container | System administration |

**MCS Categories:**
MCS categories (c0-c1023) provide isolation between containers. Each container gets unique categories, preventing one container from accessing another's files.

**Usage Examples:**

```bash
# Enable SELinux with default context
isolazi run --selinux alpine /bin/sh

# Use a custom SELinux context
isolazi run --selinux system_u:system_r:container_t:s0 alpine /bin/sh

# SELinux with specific type
isolazi run --selinux --selinux-type container_net_t alpine /bin/sh

# SELinux with MCS categories for isolation
isolazi run --selinux --selinux-mcs c100,c200 alpine /bin/sh

# Disable SELinux
isolazi run --no-selinux alpine /bin/sh

# Docker-compatible security option
isolazi run --security-opt label=system_u:system_r:container_t:s0:c100,c200 alpine /bin/sh
```

**Platform Support:**
- **Linux**: Native SELinux support (requires SELinux enabled in kernel)
- **Windows (WSL2)**: Passed through to Linux isolazi inside WSL
- **macOS (Lima)**: Passed through to Linux VM (if SELinux is available)

### Combining Security Features

For maximum security, combine multiple security layers:

```bash
# Full security stack: seccomp + AppArmor + SELinux + resource limits
isolazi run --seccomp strict \
            --apparmor \
            --selinux --selinux-mcs c100,c200 \
            --memory 512m --cpus 1 \
            alpine /bin/sh

# Production-ready secure container
isolazi run -d -p 8080:80 \
            --seccomp default \
            --apparmor my-nginx-profile \
            --selinux --selinux-type container_net_t \
            --memory 256m --cpus 0.5 \
            nginx

# Disable all security for debugging (NOT recommended for production)
isolazi run --privileged alpine /bin/sh
```

### Security Layers

Isolazi provides multiple security layers:

1. **Namespaces** - Process, mount, network, UTS, IPC, user, cgroup isolation
2. **Seccomp** - Syscall filtering to block dangerous operations
3. **AppArmor** - Mandatory Access Control for file and capability restrictions
4. **SELinux** - Type Enforcement and MCS for inter-container isolation
5. **Pivot Root** - Complete filesystem isolation
6. **User Namespace** - Run as non-root on host (rootless containers)
7. **Cgroups** - Resource limits to prevent DoS

## Network Architecture

Containers use network namespace isolation with bridge networking:

```
                     Host                          Container
              ┌─────────────────┐           ┌─────────────────┐
              │                 │           │                 │
   eth0 ──────┤   isolazi0      ├───vethXXX─┤   eth0          │
              │   172.20.0.1    │           │   172.20.0.X    │
              │   (bridge)      │           │                 │
              └─────────────────┘           └─────────────────┘
                     │
              iptables NAT
              (MASQUERADE)
```


- **Bridge**: `isolazi0` (172.20.0.1/24) - Created automatically
- **Container IPs**: 172.20.0.2 - 172.20.0.254 (auto-allocated)
- **NAT**: Outbound traffic masqueraded via host
- **Port Forwarding**: DNAT rules for `-p` published ports

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✅ Native | Full namespace isolation |
| Windows | ✅ WSL2 | Containers run in WSL2 |
| macOS | ✅ Lima | Containers run in Linux VM |

### Windows (WSL2)

On Windows, isolazi uses WSL2 as the container backend:

1. Images are pulled natively on Windows
2. Containers are executed inside WSL2 using `unshare` and `chroot`
3. Requires WSL2 to be installed (`wsl --install`)

On macOS, isolazi uses [Lima](https://github.com/lima-vm/lima) to run a lightweight Linux VM:

1. Images are pulled natively on macOS
2. Containers are executed inside a Linux VM with automatic file sharing
3. Requires macOS 12.0 (Monterey) or later
4. Needs Lima installed: `brew install lima`

#### macOS VM Management

```bash
# Check VM status and hypervisor availability
isolazi vm status

# Show VM configuration
isolazi vm info
```

#### macOS Setup

1. Install Lima:
   ```bash
   brew install lima
   ```

2. Lima automatically downloads and manages the Linux VM for isolazi on the first run.

## Data Storage

isolazi stores data in `~/.isolazi/`:

```
~/.isolazi/
├── images/
│   ├── blobs/sha256/     # Content-addressable blob storage
│   └── manifests/        # Image manifests by registry/repo/tag
└── containers/
    └── <container-id>/   # Container state and rootfs
```

## Security Notes

⚠️ **This is an educational implementation.** For production use, consider:

- ✅ User namespace support (rootless containers) - **Implemented**
- ✅ Network namespace isolation - **Implemented**
- ✅ Cgroup v2 resource limits - **Implemented**
- ✅ Seccomp syscall filtering - **Implemented**
- ✅ AppArmor profiles - **Implemented**
- ✅ SELinux labeling - **Implemented**

### Resource Limits (cgroup v2)

isolazi uses Linux cgroup v2 for resource management:

```bash
# Memory limit - container is killed if exceeded
isolazi run --memory 256m alpine stress --vm 1 --vm-bytes 512M

# CPU limit - container gets 1.5 CPU cores max
isolazi run --cpus 1.5 alpine stress --cpu 4

# Combined limits for production workloads
isolazi run -d -m 1g --cpus 2 --io-weight 100 nginx
```

**Cgroup v2 Controllers:**
| Controller | Options | Description |
|------------|---------|-------------|
| memory | `-m`, `--memory-swap` | Hard memory limit, swap limit |
| cpu | `--cpus`, `--cpu-quota`, `--cpu-period`, `--cpu-weight` | CPU quota and scheduling weight |
| io | `--io-weight` | Block I/O scheduling priority |
| oom | `--oom-score-adj`, `--oom-kill-disable` | OOM killer behavior |

**Requirements:**
- Linux kernel 4.15+ with cgroup v2 (unified hierarchy)
- cgroup v2 mounted at `/sys/fs/cgroup`
- Root or delegated cgroup permissions

### Rootless Containers

Rootless mode uses Linux user namespaces to run containers without requiring root privileges:

```bash
# Run as unprivileged user (maps your UID to root inside container)
isolazi run --rootless alpine whoami  # outputs: root

# Custom UID/GID mapping (map container root to host UID 1000)
isolazi run --rootless --uid-map 0:1000:1 --gid-map 0:1000:1 alpine id
```

**Benefits:**
- No root privileges required on the host
- Container root (UID 0) is mapped to your unprivileged user
- Improved security isolation
- Works on Linux, Windows (WSL2), and macOS (Lima)

## Requirements

### Linux
- Root privileges (CAP_SYS_ADMIN) for namespace creation, OR
- Use `--rootless` flag for unprivileged execution via user namespaces
- Kernel with namespace support (user namespace for rootless)

### Windows
- WSL2 installed and configured
- Network access for pulling images

### macOS
- macOS 12.0 (Monterey) or later
- Lima installed
- Network access for pulling images

## Benchmarking

isolazi includes a comprehensive benchmark suite for measuring container performance:

```bash
# Build the benchmark tool
zig build

# Run all benchmarks
./zig-out/bin/isolazi-bench all --rootfs /path/to/rootfs --layer /path/to/layer.tar.gz

# Run specific benchmarks
./zig-out/bin/isolazi-bench container-start --rootfs /path/to/rootfs
./zig-out/bin/isolazi-bench layer --layer /path/to/layer.tar.gz

# Export results to JSON
./zig-out/bin/isolazi-bench all -o results.json
```

**Benchmark Types:**
- **Cold Container Start** - Time from creation to first process instruction
- **Memory & CPU Overhead** - Resource consumption of idle containers
- **Layer Extraction** - OCI image layer decompression speed

See [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for detailed documentation.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## Acknowledgments

Inspired by:
- [Docker](https://www.docker.com/)
- [Podman](https://podman.io/)
- [runc](https://github.com/opencontainers/runc)
- [crun](https://github.com/containers/crun)
- [youki](https://github.com/containers/youki)
