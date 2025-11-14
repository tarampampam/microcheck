# use empty filesystem
FROM scratch

# import some executable application
COPY --from=docker.io/containous/whoami:v1.5.0 /whoami /whoami

# import httpcheck, portcheck and parallel from microcheck image
COPY --from=ghcr.io/tarampampam/microcheck:1 /bin/httpcheck /bin/portcheck /bin/parallel /bin/

# docs: <https://docs.docker.com/reference/dockerfile#healthcheck>
HEALTHCHECK --interval=5s --retries=2 CMD ["parallel", \
    "httpcheck http://127.0.0.1:8080", \
    "portcheck --port 8080" \
]

ENTRYPOINT ["/whoami", "-port", "8080"]
