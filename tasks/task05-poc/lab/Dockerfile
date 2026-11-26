FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bridge-utils \
        iproute2 \
        iputils-ping \
        mininet \
        openssl \
        python3 \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY api.py config.py dga.py host.py scenario.py sensor.py state.py topology.py services.py /app/

EXPOSE 8080
CMD ["python3", "/app/api.py"]
