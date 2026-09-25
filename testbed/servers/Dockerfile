FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 DEBIAN_FRONTEND=noninteractive

# tcpdump captures; wireshark-common supplies capinfos for the frame count.
RUN echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections \
    && apt-get update \
    && apt-get install -y --no-install-recommends tcpdump tshark openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir aiosmtpd==1.4.6 cryptography==44.0.0

WORKDIR /app
COPY . /app

# Runs as root: tcpdump needs CAP_NET_RAW, and this container exists only to
# generate test captures on its own loopback interface. It is never deployed.
ENTRYPOINT ["python", "runner.py"]
