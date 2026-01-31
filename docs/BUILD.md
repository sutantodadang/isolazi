# Building Container Images

`isolazi` includes a built-in image builder that supports the OCI standard. You can build images using an `Isolazifile` or a standard `Dockerfile`.

## Basic Usage

Run the `build` command in the directory containing your `Isolazifile`:

```bash
isolazi build -t my-image:latest .
```

To use a specific file name:

```bash
isolazi build -f Dockerfile.dev -t my-app:dev .
```

## Build Options

| Option | Description |
|--------|-------------|
| `-t, --tag <name>` | Name and optionally a tag in `name:tag` format (e.g., `my-image:v1`). |
| `-f, --file <path>` | Path to the Isolazifile (default: `Isolazifile` or `Dockerfile`). |
| `--build-arg <arg>` | Set build-time variables (e.g., `--build-arg VERSION=1.0`). |
| `--no-cache` | Do not use cache when building the image. |
| `-q, --quiet` | Suppress build output and print image ID on success. |

## Isolazifile Reference

`isolazi` supports standard Dockerfile syntax.

### FROM
Specifies the base image. Must be the first instruction.

```dockerfile
FROM alpine:latest
FROM ubuntu:22.04 AS builder
```

### RUN
Executes commands in a new layer.

```dockerfile
# Shell form (uses /bin/sh -c)
RUN apk add --no-cache curl

# Exec form
RUN ["/bin/my-app", "--init"]
```

### COPY
Copies files from the build context to the container.

```dockerfile
COPY src/ /app/src/
COPY --chown=user:group config.json /app/config.json
```

### ADD
Similar to `COPY`, but can also extract tar archives and download URLs.

```dockerfile
ADD https://example.com/file.tar.gz /tmp/
```

### CMD
Provides defaults for an executing container. Can be overridden at runtime.

```dockerfile
CMD ["/app/server"]
```

### ENTRYPOINT
Configures a container that will run as an executable.

```dockerfile
ENTRYPOINT ["/usr/bin/python3"]
CMD ["main.py"]
```

### ENV
Sets environment variables that persist in the container.

```dockerfile
ENV PORT=8080
ENV APP_HOME=/app
```

### WORKDIR
Sets the working directory for subsequent instructions.

```dockerfile
WORKDIR /app
```

### EXPOSE
Informs the runtime about network ports the container listens on (documentation only).

```dockerfile
EXPOSE 80/tcp
EXPOSE 53/udp
```

### ARG
Defines variables that users can pass at build-time.

```dockerfile
ARG VERSION=1.0
RUN echo "Building version $VERSION"
```

### VOLUME
Creates a mount point and links it to an externally mounted volume.

```dockerfile
VOLUME ["/data"]
```

### USER
Sets the user name (or UID) for subsequent `RUN`, `CMD`, and `ENTRYPOINT` instructions.

```dockerfile
USER nobody
```

## Multi-Stage Builds

Isolazi supports multi-stage builds to keep final images small.

```dockerfile
# Stage 1: Build
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o myapp main.go

# Stage 2: Runtime
FROM alpine:latest
COPY --from=builder /app/myapp /usr/local/bin/myapp
CMD ["myapp"]
```
