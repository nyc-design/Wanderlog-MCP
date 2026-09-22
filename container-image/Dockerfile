# Build the upstream CLI from an immutable revision; no Coder base image.
FROM golang:1.26.6-bookworm AS cli
ARG WANDERLOG_COMMIT=6d27c324c4aeca54ee1bf027d41e9f415e329734
WORKDIR /src
RUN git init . \
    && git remote add origin https://github.com/denysvitali/wanderlog-cli.git \
    && git fetch --depth=1 origin "${WANDERLOG_COMMIT}" \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${WANDERLOG_COMMIT}" \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/wanderlog .

FROM python:3.13-slim-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl git sudo util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /bin/bash coder \
    && printf 'coder ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/coder \
    && chmod 0440 /etc/sudoers.d/coder
ENV STATE_DIR=/home/coder/.local/share/wanderlog-mcp \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
COPY mcp/requirements.txt /mcp/requirements.txt
RUN pip install --no-cache-dir -r /mcp/requirements.txt
COPY --from=cli /out/wanderlog /usr/local/bin/wanderlog
COPY mcp/ /opt/wanderlog-mcp/mcp/
COPY --chmod=0755 container-image/start-gateway /usr/local/bin/start-gateway
RUN install -d -o coder -g coder -m 0700 /home/coder/.local/share/wanderlog-mcp
USER coder
WORKDIR /opt/wanderlog-mcp
EXPOSE 8080
# Ordinary Docker runs stay in the foreground. Envbuilder supplies its own init.
CMD ["python", "/opt/wanderlog-mcp/mcp/server.py"]
