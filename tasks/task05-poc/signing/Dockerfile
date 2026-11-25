FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY initialize-keys.sh /usr/local/bin/initialize-keys
RUN chmod 0555 /usr/local/bin/initialize-keys

ENTRYPOINT ["/usr/local/bin/initialize-keys"]
