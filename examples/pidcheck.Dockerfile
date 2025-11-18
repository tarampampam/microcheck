FROM docker.io/library/nginx:1.25-alpine

# import pidcheck from microcheck image
COPY --from=ghcr.io/tarampampam/microcheck:1 /bin/pidcheck /bin/pidcheck

# nginx writes its PID to /var/run/nginx.pid by default
HEALTHCHECK --interval=5s --retries=2 CMD ["pidcheck", "--file", "/var/run/nginx.pid"]
