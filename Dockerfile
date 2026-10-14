# botpolice listener container.
#
# The core listener is standard-library only. Flask is installed only when the
# optional dashboard is requested at build time:
#     docker build --build-arg INSTALL_DASHBOARD=1 -t botpolice .
#
# Build with Docker or Podman:
#     podman build -t botpolice .
FROM python:3.12-slim

# Optional dashboard dependency (Flask). Off by default to keep the image
# dependency-free.
ARG INSTALL_DASHBOARD=0

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE NOTICE requirements.txt adb_responses.example.json ./
COPY botpolice ./botpolice

RUN pip install . \
 && if [ "$INSTALL_DASHBOARD" = "1" ]; then pip install -r requirements.txt; fi

# Non-root, unprivileged user. UID is fixed so volume permissions are stable.
RUN groupadd --gid 10001 botpolice \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin botpolice \
 && mkdir -p /data /home/botpolice \
 && chown -R 10001:10001 /data /home/botpolice

USER 10001:10001
WORKDIR /data

# Only /data (logs, canary store, generated decoys) should be writable.
VOLUME ["/data"]

# Decoy ports (all above 1024). Actual exposure is controlled in compose.
EXPOSE 2222 8080 11435 15432 5555

ENTRYPOINT ["botpolice"]
CMD ["run", "--config", "/data/config.json"]
