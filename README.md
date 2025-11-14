<p align="center">
  <a href="https://github.com/tarampampam/microcheck#readme">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://socialify.git.ci/tarampampam/microcheck/image?description=1&font=Raleway&forks=1&issues=1&logo=https%3A%2F%2Fupload.wikimedia.org%2Fwikipedia%2Fcommons%2Fa%2Fa7%2FDocker-svgrepo-com.svg&owner=1&pulls=1&pattern=Solid&stargazers=1&theme=Dark">
      <img align="center" src="https://socialify.git.ci/tarampampam/microcheck/image?description=1&font=Raleway&forks=1&issues=1&logo=https%3A%2F%2Fupload.wikimedia.org%2Fwikipedia%2Fcommons%2Fa%2Fa7%2FDocker-svgrepo-com.svg&owner=1&pulls=1&pattern=Solid&stargazers=1&theme=Light">
    </picture>
  </a>
</p>

# Lightweight health check utilities for Docker containers

Minimal, statically linked tools designed for [container health checks][docker-healthcheck]. Built with musl for
minimal size and zero dependencies.

A common use case is to include these tools in `HEALTHCHECK` instructions in Dockerfiles, allowing Docker to
monitor the health of applications running inside containers. Typically, you
[don't need them in Kubernetes][k8s-probes] (because Kubernetes has its own health check mechanisms, where the
kubelet periodically checks the container's status), but in vanilla Docker or other container runtimes without
built-in health checks, these tools can be very useful.

You might say, "But why? There are already tools like `curl` or `wget`!". That's true, but those tools are often
quite large because they include many features and dependencies. Using them only for health checks can
unnecessarily increase the size of your Docker images. These tools are designed to be as small as possible
while still providing the required functionality, especially for `scratch` or `distroless` images (`curl` and
`wget` **won't work there** at all, since they rely on shared libraries). In addition, their exit codes are
designed to match Docker's expectations for health checks (0 = healthy, 1 = unhealthy), whereas `curl` and
`wget` do not follow this convention.

Just to illustrate the size difference, here is a comparison of adding `httpcheck` versus `curl` or `wget`:

```
COPY --from=... /bin/httpcheck  [▌--------------------------------------] 75Kb
apk add wget                    [███████████████████--------------------] 3.3Mb // 44× larger
apt install wget                [█████████████████████------------------] 4Mb   // 53× larger
apk add curl                    [██████████████████████████-------------] 5.2Mb // 69× larger
apt install curl                [███████████████████████████████████████] 9.3Mb // 124× larger
```

So, think of this as an alternative to:

```diff
-# install curl for health checks (+~10MB)
-RUN apt update && apt install -y curl && rm -r /var/lib/apt/lists/*
-
-HEALTHCHECK --interval=5m --timeout=3s CMD curl -f http://localhost:8080/ || exit 1
+# add httpcheck binary (+~75KB)
+COPY --from=ghcr.io/tarampampam/microcheck:1 /bin/httpcheck /bin/httpcheck
+
+HEALTHCHECK --interval=5m --timeout=3s CMD ["httpcheck", "http://localhost:8080/"]
```

> [!NOTE]
> By the way - the first approach also creates a shell process (adding unnecessary overhead) and depends on the
> shell being present in the container, which may not be the case in minimal images.

[docker-healthcheck]: https://docs.docker.com/reference/dockerfile/#healthcheck
[k8s-probes]: https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/

## 🔥 Features

* **Statically linked**: Works in minimal containers (e.g., `scratch`, `distroless`)
* **Pretty fast**: Written in pure `C`, compiled with `musl`
* **Multi-arch and cross-compiled** (x86_64, ARM, etc.)
* **Distributed** as single binaries (see the releases page) and Docker image
* **Minimal size**: Optimized for small Docker images
* **TLS support**: Uses `mbedTLS` for HTTPS (accepts self-signed certificates and does NOT verify SSL/TLS certificates)
* **Protocol auto-detection** (`httpscheck` only): Automatically tries HTTPS first, falls back to HTTP on TLS errors
* **Flexible configuration**: Command-line flags and environment variables
* **Docker-friendly**: Handles signals (`SIGTERM`, `SIGINT`) gracefully

## 🧩 Tools

| Tool         |  Size  | Use case                          |
|--------------|:------:|-----------------------------------|
| `httpcheck`  | ~75KB  | Check HTTP (only) endpoints       |
| `httpscheck` | ~500KB | Check HTTP and HTTPS endpoints    |
| `portcheck`  | ~70KB  | Check TCP/UDP ports               |
| `parallel`   | ~50KB  | Run multiple commands in parallel |

### `httpcheck` & `httpscheck`

Those tools perform HTTP health checks. `httpscheck` includes TLS support, while `httpcheck` does not to reduce
the binary file size. Both tools share the same command-line interface, and even compile from the same source
code (but with different build flags).

> [!NOTE]
> `httpscheck` supports **protocol auto-detection**: when no protocol (`http://` or `https://`) is specified in the URL,
> it will first attempt an HTTPS connection. If the HTTPS connection fails (TLS handshake error), it will automatically
> fall back to HTTP. This is useful for applications that may have TLS enabled or disabled based on configuration.

```
Options:
  -h, --help               Show this help message
      --host               Override hostname from URL (env: CHECK_HOST)
      --host-env           Change env variable name for --host (current: CHECK_HOST)
  -p, --port               Override port from URL (env: CHECK_PORT)
      --port-env           Change env variable name for --port (current: CHECK_PORT)
  -m, --method             HTTP method (env: CHECK_METHOD) (default: GET)
      --method-env         Change env variable name for --method (current: CHECK_METHOD)
  -u, --user-agent         User-Agent header (env: CHECK_USER_AGENT) (default: healthcheck/0.0.0 (httpcheck))
      --user-agent-env     Change env variable name for --user-agent (current: CHECK_USER_AGENT)
  -H, --header             Add custom HTTP header (can be used multiple times)
      --basic-auth         Basic auth credentials (username:password, env: CHECK_BASIC_AUTH)
      --basic-auth-env     Change env variable name for --basic-auth (current: CHECK_BASIC_AUTH)
  -t, --timeout            Request timeout in seconds (env: CHECK_TIMEOUT) (default: 5)
      --timeout-env        Change env variable name for --timeout (current: CHECK_TIMEOUT)
```

**URL Format Examples:**

```shell
# Explicit HTTP
httpscheck http://localhost:8080/health

# Explicit HTTPS
httpscheck https://localhost:8080/health

# Auto-detect (httpscheck only): tries HTTPS first, falls back to HTTP on TLS error
httpscheck localhost:8080/health
```

### `portcheck`

This tool checks if a TCP or UDP port is open on a given host (usually `127.0.0.1`). For TCP, it attempts to
establish a connection, while for UDP... Since UDP is connectionless - very frequently it may not be possible to
determine if the port is open or closed.

> [!IMPORTANT]
> Most UDP servers respond only to valid protocol requests. This tool sends nearly empty UDP datagram,
> which may not receive a response from many services. Use UDP checks only when you are certain the target
> will respond appropriately.

```
Options:
  -h, --help               Show this help message
      --tcp                Use TCP protocol (default)
      --udp                Use UDP protocol
      --host               Target hostname or IPv4 address (env: CHECK_HOST) (default: 127.0.0.1)
      --host-env           Change env variable name for --host (current: CHECK_HOST)
  -p, --port               Target port number (env: CHECK_PORT, required)
      --port-env           Change env variable name for --port (current: CHECK_PORT)
  -t, --timeout            Check timeout in seconds (env: CHECK_TIMEOUT) (default: 5)
      --timeout-env        Change env variable name for --timeout (current: CHECK_TIMEOUT)
```

#### Environment Variable Overrides

Most options can be overridden via environment variables. This is useful in Docker containers, where you may
want to configure health checks without modifying the command line. For example:

```shell
# Use a custom method via environment variable
CHECK_METHOD=HEAD httpcheck http://127.0.0.1

# If the application already uses the APP_PORT variable, you can map it to override the port used by httpcheck
APP_PORT=8080 httpcheck --port-env=APP_PORT http://127.0.0.1
```

### `parallel`

This tool executes multiple commands in parallel and is designed specifically for Docker health checks where you
need to verify multiple conditions simultaneously. It returns exit code 0 only if all commands succeed, or the
exit code of the first failed command otherwise.

The main use case is combining multiple health checks (HTTP endpoints, TCP ports, etc.) into a single
`HEALTHCHECK` instruction. When any command fails, `parallel` immediately terminates all other running commands
and returns the failure code, ensuring fast failure detection.

```
Options:
  -h, --help               Show this help message
  -j, --jobs               Limit number of parallel jobs (default: unlimited)
```

#### Argument Parsing

Commands can be specified as:

- Unquoted words for simple commands: `parallel whoami id`
- Quoted strings for commands with arguments: `parallel "echo hello" "echo world"`
- Mixed quoted/unquoted parts that concatenate: `parallel cmd'arg1 arg2'"arg3"`

Inside quoted strings:

- Single quotes preserve everything literally (no escaping)
- Double quotes allow backslash escaping
- Spaces and tabs separate arguments
- Adjacent quoted/unquoted parts concatenate into single argument

## 🐋 Docker image

| Registry                           | Image                            |
|------------------------------------|----------------------------------|
| [GitHub Container Registry][ghcr]  | `ghcr.io/tarampampam/microcheck` |
| [Red Hat Container Registry][quay] | `quay.io/tarampampam/microcheck` |
| [Docker Hub][docker-hub]           | `tarampampam/microcheck`         |

[docker-hub]:https://hub.docker.com/r/tarampampam/microcheck
[ghcr]:https://github.com/users/tarampampam/packages/container/package/microcheck
[quay]:https://quay.io/repository/tarampampam/microcheck

> [!IMPORTANT]
> Using the `latest` tag for the Docker image is highly discouraged due to potential backward-incompatible changes
> during **major** upgrades. Please use tags in the `X.Y.Z`, `X.Y`, or at least `X` format.

The following platforms for this image are available:

```shell
$ docker run --rm mplatform/mquery ghcr.io/tarampampam/microcheck:1
Image: ghcr.io/tarampampam/microcheck:1
 * Manifest List: Yes (Image type: application/vnd.oci.image.index.v1+json)
 * Supported platforms:
   - linux/386
   - linux/amd64
   - linux/arm/v6
   - linux/arm/v7
   - linux/arm64
   - linux/ppc64le
   - linux/s390x
```

## ⚙ Pre-compiled binaries

Pre-compiled static binaries are available on the [releases page][releases-page]. Download the appropriate binary
for your architecture and operating system.

[releases-page]: https://github.com/tarampampam/microcheck/releases

## 🔌 Usage examples

<details>
  <summary><strong>🚀 Healthcheck for HTTP server</strong></summary>

```Dockerfile
# use empty filesystem
FROM scratch

# import some executable application
COPY --from=docker.io/containous/whoami:v1.5.0 /whoami /whoami

# import httpcheck from current repository image (exactly 'httpcheck' due
# to we don't need TLS here)
COPY --from=ghcr.io/tarampampam/microcheck:1 /bin/httpcheck /bin/httpcheck

# docs: <https://docs.docker.com/reference/dockerfile#healthcheck>
HEALTHCHECK --interval=5s --retries=2 CMD ["httpcheck", "http://127.0.0.1:8080/health"]

ENTRYPOINT ["/whoami", "-port", "8080"]
```

Let's build it and run:

```shell
$ docker build -t http-check:local - < ./examples/http-check.Dockerfile
$ docker run --rm -d --name http-check http-check:local
$ docker ps --filter 'name=http-check' --format '{{.Status}}'
Up 6 seconds (healthy)
$ docker kill http-check
```

</details>

<details>
  <summary><strong>🚀 Multiple health checks with parallel</strong></summary>

This example shows how to use `parallel` to check multiple conditions simultaneously. The container is
considered healthy only if all checks pass:

```Dockerfile
FROM scratch

# import some executable application
COPY --from=docker.io/containous/whoami:v1.5.0 /whoami /whoami

# import httpcheck, portcheck and parallel from microcheck image
COPY --from=ghcr.io/tarampampam/microcheck:1 /bin/httpcheck /bin/portcheck /bin/parallel /bin/

# check both HTTP endpoint AND port using parallel (the port usually will differ from the HTTP port)
HEALTHCHECK --interval=5s --retries=2 CMD ["parallel", \
    "httpcheck http://127.0.0.1:8080", \
    "portcheck --port 8080" \
]

ENTRYPOINT ["/whoami", "-port", "8080"]
```

Let's build it and run:

```shell
$ docker build -t parallel:local - < ./examples/parallel.Dockerfile
$ docker run --rm -d --name parallel parallel:local
$ docker ps --filter 'name=parallel' --format '{{.Status}}'
Up 6 seconds (healthy)
$ docker kill parallel
```

</details>

<details>
  <summary><strong>🚀 Healthcheck with protocol auto-detection</strong></summary>

This example demonstrates the protocol auto-detection feature of `httpscheck`, which is useful when your application
may have TLS enabled or disabled based on configuration:

```Dockerfile
# use empty filesystem
FROM scratch

# import your application (example assumes it can run with or without TLS)
COPY --from=your-app:latest /app /app

# import httpscheck to enable auto-detection
COPY --from=ghcr.io/tarampampam/microcheck:1 /bin/httpscheck /bin/httpscheck

# healthcheck will try HTTPS first, fall back to HTTP if TLS is not available
# note: no http:// or https:// prefix in the URL
HEALTHCHECK --interval=5s --retries=2 CMD ["httpscheck", "127.0.0.1:8080/health"]

ENTRYPOINT ["/app"]
```

**How it works:**

1. When no protocol is specified (`127.0.0.1:8080/health` instead of `https://...`), `httpscheck`
   first attempts an HTTPS connection
2. If the HTTPS handshake fails (TLS error), it automatically falls back to HTTP
3. This happens silently without any output, making it transparent for health checks
4. The fallback only occurs on connection/TLS errors, not on HTTP status codes (`4xx`, `5xx`)

This is particularly useful for:
- Applications with optional TLS configuration
- Development vs production environments
- Gradual TLS rollouts

</details>

<details>
  <summary><strong>🚀 Healthcheck for TCP server</strong></summary>

The same as previous, but using `portcheck`:

```Dockerfile
# use empty filesystem
FROM scratch

# import some executable application
COPY --from=docker.io/containous/whoami:v1.5.0 /whoami /whoami

# import portcheck because we need only TCP port check here
COPY --from=ghcr.io/tarampampam/microcheck:1 /bin/portcheck /bin/portcheck

# docs: <https://docs.docker.com/reference/dockerfile#healthcheck>
HEALTHCHECK --interval=5s --retries=2 CMD ["portcheck", "--port", "8080"]

ENTRYPOINT ["/whoami", "-port", "8080"]
```

Let's build it and run:

```shell
$ docker build -t tcp-check:local - < ./examples/tcp-check.Dockerfile
$ docker run --rm -d --name tcp-check tcp-check:local
$ docker ps --filter 'name=tcp-check' --format '{{.Status}}'
Up 7 seconds (healthy)
$ docker kill tcp-check
```

</details>

## 🎁 Bonus level - adding healthcheck to popular images

Since you're here, you might find it useful to know how to healthcheck some popular Docker images (you don't need
tools from this repository for that, but it might be interesting anyway):

<details>
  <summary><strong>🧪 PostgreSQL</strong></summary>

> PostgreSQL, often simply "Postgres", is an object-relational database management system (ORDBMS) with an emphasis
> on extensibility and standards-compliance.

```yaml
# compose.yml

services:
  postgresql:
    image: docker.io/library/postgres:18-alpine
    environment:
      POSTGRES_DB: some_dbname # POSTGRES_DATABASE in older versions
      POSTGRES_USER: some_user
      POSTGRES_PASSWORD: some_password
    ports: ['5432/tcp']
    healthcheck:
      test: ['CMD', 'pg_isready', '-U', 'some_user', '-d', 'some_dbname']
      interval: 10s
```

</details>

<details>
  <summary><strong>🧪 Temporal</strong></summary>

> Temporal is a scalable and reliable runtime for durable function executions.

```yaml
# compose.yml

services:
  temporal:
    image: docker.io/temporalio/auto-setup:1.28.1
    environment:
      BIND_ON_IP: 0.0.0.0
    ports: ['7233/tcp']
    healthcheck:
      test: ['CMD', 'tctl', '--address', '127.0.0.1:7233', 'workflow', 'list']
      interval: 10s
```

</details>

<details>
  <summary><strong>🧪 Jaeger</strong></summary>

> Jaeger is an open-source, distributed tracing platform used to monitor and troubleshoot complex
> microservices architectures.

```yaml
# compose.yml

services:
  jaeger:
    image: docker.io/jaegertracing/all-in-one:1.60
    ports: ['6831/udp', '16686/tcp', '4318/tcp']
    healthcheck:
      test: ['CMD', 'wget', '--spider', '-q', 'http://127.0.0.1:14269/healthz']
      interval: 10s
```

</details>

<details>
  <summary><strong>🧪 Minio</strong></summary>

> MinIO is a high-performance, Kubernetes-native object storage system that is compatible with the Amazon S3 API.

```yaml
# compose.yml

services:
  minio:
    image: quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z
    command: server /data --json --console-address ':9090'
    ports: ['9000/tcp', '9090/tcp']
    healthcheck:
      test: ['CMD', 'curl', '-f', 'http://127.0.0.1:9000/minio/health/live']
      interval: 10s
```

</details>

<details>
  <summary><strong>🧪 MySQL</strong></summary>

> MySQL is an open-source relational database management system (RDBMS).

```yaml
# compose.yml

services:
  mysql:
    image: docker.io/library/mysql:9
    environment:
      MYSQL_RANDOM_ROOT_PASSWORD: 'true'
      MYSQL_DATABASE: some_dbname
      MYSQL_USER: some_user
      MYSQL_PASSWORD: some_password
    ports: ['3306/tcp', '3306/tcp'] # use port 32601 for local development
    healthcheck:
      test: ['CMD', 'mysql', '-h', '127.0.0.1', '--user=some_user', '--password=some_password', '--execute', 'SELECT 1']
      interval: 10s
```

</details>

<details>
  <summary><strong>🧪 Redis</strong></summary>

> Redis is an open-source, in-memory data structure store used as a database, cache, and message broker.

```yaml
# compose.yml

services:
  redis:
    image: docker.io/library/redis:8-alpine
    ports: ['6379/tcp']
    healthcheck:
      test: ['CMD', 'redis-cli', 'ping']
      interval: 10s
```

</details>

<details>
  <summary><strong>🧪 Adminer (phpMinAdmin)</strong></summary>

> Adminer (formerly phpMinAdmin) is a full-featured database management tool written in PHP.

```yaml
# compose.yml

services:
  adminer:
    image: docker.io/library/adminer:5
    ports: ['8080/tcp']
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/"]
      interval: 10s
```

</details>

<details>
  <summary><strong>🧪 Caddy</strong></summary>

> Caddy 2 is a powerful, enterprise-ready, open source web server with automatic HTTPS written in Go.

```yaml
# compose.yml

services:
  caddy:
    image: docker.io/library/caddy:2-alpine
    ports: ['80/tcp', '443/tcp']
    healthcheck:
      test: ['CMD', 'wget', '--spider', '-q', 'http://127.0.0.1:80/']
      interval: 10s
```

</details>

<details>
  <summary><strong>🧪 Cassandra</strong></summary>

> Apache Cassandra is an open source distributed database management system designed to handle large amounts of
> data across many commodity servers, providing high availability with no single point of failure.

```yaml
# compose.yml

services:
  cassandra:
    image: docker.io/library/cassandra:5
    ports: ['9042/tcp']
    healthcheck:
      test: ['CMD', 'cqlsh', '-e', 'DESCRIBE KEYSPACES', '127.0.0.1', '9042']
      interval: 10s
      start_period: 60s # <-- important
```

</details>

> [!TIP]
> Feel free to contribute more examples via pull requests!

## 🏗 Building from sources

To build the tools from sources, ensure you have the following dependencies installed:

* `musl-gcc`
* `cmake`
* `wget`
* `patch`
* Standard build tools (`make`, `tar`)
* Optionally - `clang-format`

After cloning the repository, build the tools using the `Makefile` - execute `make`.

For testing, you need `python3` and `openssl` installed. Run tests with `make test`.

## 👾 Support

[![Issues][badge-issues]][issues]
[![Issues][badge-prs]][prs]

If you encounter any bugs in the project, please [create an issue][new-issue] in this repository.

[badge-issues]:https://img.shields.io/github/issues/tarampampam/microcheck.svg?maxAge=45
[badge-prs]:https://img.shields.io/github/issues-pr/tarampampam/microcheck.svg?maxAge=45
[issues]:https://github.com/tarampampam/microcheck/issues
[prs]:https://github.com/tarampampam/microcheck/pulls
[new-issue]:https://github.com/tarampampam/microcheck/issues/new/choose

## 📖 License

This is open-sourced software licensed under the [MIT License][license].

[license]:https://github.com/tarampampam/microcheck/blob/master/LICENSE
