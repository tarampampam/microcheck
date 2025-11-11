# use empty filesystem
FROM scratch

# import some executable application
COPY --from=docker.io/containous/whoami:v1.5.0 /whoami /whoami

# import httpcheck from current repository image (exactly 'httpcheck' due
# to we don't need TLS here)
COPY --from=ghcr.io/tarampampam/microcheck /bin/httpcheck /bin/httpcheck

# docs: <https://docs.docker.com/reference/dockerfile#healthcheck>
HEALTHCHECK --interval=5s --retries=2 CMD ["httpcheck", "http://127.0.0.1:80"]

ENTRYPOINT ["/whoami"]
