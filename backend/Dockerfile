FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

# tshark pulls in wireshark-common, which provides capinfos / editcap / mergecap.
# Preseed the setuid prompt to "no": nothing in this image captures live traffic,
# it only reads files, so the dumpcap helper must stay unprivileged.
RUN echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        tshark \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Parsers are the attack surface of this product: uploaded files are hostile input.
# Everything below runs as an unprivileged user.
RUN useradd --create-home --uid 10001 smscope

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /data && chown -R smscope:smscope /data /app

USER smscope

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
