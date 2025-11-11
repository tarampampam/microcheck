# Lightweight health check utilities for Docker containers

Minimal, statically linked tools designed for [container health checks][docker-healthcheck]. Built with musl for
minimal size and zero dependencies.

A common use case is to include these tools in `HEALTHCHECK` instructions in Dockerfiles, allowing Docker to
monitor the health of applications running inside containers. Typically, you
[don't need them in Kubernetes][k8s-probes] (because Kubernetes has its own health check mechanisms, where the
kubelet periodically checks the container’s status), but in vanilla Docker or other container runtimes without
built-in health checks, these tools can be very useful.

You might say, "But why? There are already tools like `curl` or `wget`!" That’s true, but those tools are often
quite large because they include many features and dependencies. Using them only for health checks can
unnecessarily increase the size of your Docker images. These tools are designed to be as small as possible
while still providing the required functionality, especially for `scratch` or `distroless` images (`curl` and
`wget` **won’t work there** at all, since they rely on shared libraries). In addition, their exit codes are
designed to match Docker’s expectations for health checks (0 = healthy, 1 = unhealthy), whereas `curl` and
`wget` do not follow this convention.

So, think of this as an alternative to:

```diff
-HEALTHCHECK --interval=5m --timeout=3s CMD curl -f http://localhost:8080/ || exit 1
+HEALTHCHECK --interval=5m --timeout=3s CMD ["httpcheck", "http://localhost:8080/"]
```

> [!NOTE]
> By the way - the first approach also creates a shell process (adding unnecessary overhead) and depends on the
> shell being present in the container, which may not be the case in minimal images.

[docker-healthcheck]: https://docs.docker.com/reference/dockerfile/#healthcheck
[k8s-probes]: https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/

## Features

* **Statically linked**: Works in minimal containers (e.g., `scratch`, `distroless`)
* **Pretty fast**: Written in pure `C`, compiled with `musl`
* **Multi-arch and cross-compiled** (x86_64, ARM, etc.)
* **Distributed** as single binaries (see the releases page) and Docker images
* **Minimal size**: Optimized for small Docker images
* **TLS support**: Uses `mbedTLS` for HTTPS (accepts self-signed certificates)
* **Flexible configuration**: Command-line flags and environment variables
* **Docker-friendly**: Handles signals (`SIGTERM`, `SIGINT`) gracefully

## Tools

| Tool         |  Size  | Use case                       |
|--------------|:------:|--------------------------------|
| `httpcheck`  | ~75KB  | Check HTTP (only) endpoints    |
| `httpscheck` | ~500KB | Check HTTP and HTTPS endpoints |
| `portcheck`  | ~70KB  | Check TCP/UDP ports            |

### `httpcheck` & `httpscheck`

Options:

```
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

### `portcheck`

```
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

## Building from source

To build the tools from source, ensure you have the following dependencies installed:

* `musl-gcc`
* `cmake`
* `wget`
* `patch`
* Standard build tools (`make`, `tar`)

After cloning the repository, build the tools using the `Makefile` - `make all`.

For testing, you need `python3` and `openssl` installed. Run tests with `make test`.
