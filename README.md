# isolazi

A minimal container runtime written in Zig, inspired by Docker, Podman, and OCI runtimes (runc, crun, youki).

## Features

- 🐳 **Docker-like CLI** - Familiar commands: `run`, `pull`, `ps`, `stop`, `rm`
- 📦 **OCI Image Support** - Pull images from Docker Hub and other registries
- 🔒 **Process Isolation** - Linux namespaces (PID, mount, UTS, IPC)
- 🗂️ **Filesystem Isolation** - Using `pivot_root` or `chroot`
- 🪟 **Windows Support** - Run containers via WSL2 backend
- 🍎 **macOS Support** - Run containers via Apple Virtualization framework
- ⚡ **Fast & Lightweight** - Written in Zig with minimal dependencies

## Installation

### Prerequisites

- [Zig](https://ziglang.org/download/) 0.15.2 or later
- Linux kernel with namespace support (for native execution)
- WSL2 (for Windows)
- macOS 12.0+ with vfkit or Lima (for macOS)

### Build from Source

```bash
git clone https://github.com/nicefacer/isolazi.git
cd isolazi
zig build -Doptimize=ReleaseFast
```

The binary will be available at `zig-out/bin/isolazi`.

## Quick Start

### Pull an Image

```bash
isolazi pull alpine:latest
```

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

# With port publishing
isolazi run -d -p 8080:80 nginx

# Run PostgreSQL with all options
isolazi run -d -p 5432:5432 \
  -e POSTGRES_PASSWORD=secret,POSTGRES_USER=myuser,POSTGRES_DB=mydb \
  -v /mydata:/var/lib/postgresql/data \
  postgres:16-alpine
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
    create [--name NAME] <image>     Create a container without starting
    start <container>                Start a stopped container
    stop <container>                 Stop a running container
    rm [-f] <container>              Remove a container
    ps [-a]                          List containers
    inspect <container>              Display container details
    pull <image>                     Pull an image from a registry
    images                           List cached images
    prune                            Remove stopped containers and unused images
    version                          Print version information
    help                             Print this help message

OPTIONS for 'run':
    -d, --detach              Run container in background
    -e, --env KEY=VALUE       Set environment variable (comma-separated: KEY1=V1,KEY2=V2)
    -v, --volume SRC:DST[:ro] Mount a volume (can be repeated)
    -p, --port HOST:CONTAINER Publish container port to host (can be repeated)
    --hostname <name>         Set the container hostname
    --cwd <path>              Set the working directory

OPTIONS for 'ps':
    -a, --all            Show all containers (default: only running)

OPTIONS for 'rm':
    -f, --force          Force remove running container
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
│   ├── linux/            # Linux-specific (namespaces)
│   ├── fs/               # Filesystem operations
│   ├── windows/          # WSL2 backend
│   └── macos/            # Apple Virtualization backend
├── build.zig
└── build.zig.zon
```

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✅ Native | Full namespace isolation |
| Windows | ✅ WSL2 | Containers run in WSL2 |
| macOS | ✅ Virtualization | Containers run in Linux VM |

### Windows (WSL2)

On Windows, isolazi uses WSL2 as the container backend:

1. Images are pulled natively on Windows
2. Containers are executed inside WSL2 using `unshare` and `chroot`
3. Requires WSL2 to be installed (`wsl --install`)

### macOS (Apple Virtualization)

On macOS, isolazi uses Apple's Virtualization framework to run a lightweight Linux VM:

1. Images are pulled natively on macOS
2. Containers are executed inside a Linux VM using VirtioFS for filesystem sharing
3. Requires macOS 12.0 (Monterey) or later
4. Needs a hypervisor backend:
   - **vfkit** (recommended): `brew install vfkit` - Uses native Virtualization.framework
   - **Lima**: `brew install lima` - Easy-to-use Linux VM manager with automatic file sharing

#### macOS VM Management

```bash
# Check VM status and hypervisor availability
isolazi vm status

# Show VM configuration
isolazi vm info
```

#### macOS Setup

1. Install a hypervisor:
   ```bash
   # Recommended: vfkit (native, fast, requires manual kernel setup)
   brew install vfkit
   
   # Alternative: Lima (easier setup, auto-manages VM)
   brew install lima
   ```

2. For vfkit users - download Linux kernel:
   ```bash
   mkdir -p ~/Library/Application\ Support/isolazi/vm
   # Place your vmlinuz kernel file there
   ```

3. Lima users don't need manual kernel setup - Lima automatically downloads and manages the Linux VM.

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

- User namespace support (rootless containers)
- Seccomp filters
- AppArmor/SELinux profiles
- Proper cgroup limits
- Network namespace isolation

## Requirements

### Linux
- Root privileges (CAP_SYS_ADMIN) for namespace creation
- Kernel with namespace support

### Windows
- WSL2 installed and configured
- Network access for pulling images

### macOS
- macOS 12.0 (Monterey) or later
- vfkit or Lima installed
- Network access for pulling images

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
