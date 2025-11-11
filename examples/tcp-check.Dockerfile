# use empty filesystem
FROM scratch

# import some executable application
COPY --from=docker.io/containous/whoami:v1.5.0 /whoami /whoami

# import portcheck because we need only TCP port check here
COPY --from=ghcr.io/tarampampam/microcheck /bin/portcheck /bin/portcheck

# docs: <https://docs.docker.com/reference/dockerfile#healthcheck>
HEALTHCHECK --interval=5s --retries=2 CMD ["portcheck", "--port", "8080"]

ENTRYPOINT ["/whoami", "-port", "8080"]
