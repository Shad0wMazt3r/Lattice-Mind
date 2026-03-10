FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git \
    curl wget nmap netcat-openbsd \
    binwalk exiftool file \
    dirb \
    steghide foremost \
    && rm -rf /var/lib/apt/lists/*

# Install ffuf (Go binary — not in apt)
RUN ARCH=$(dpkg --print-architecture) && \
    wget -q "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_${ARCH}.tar.gz" -O /tmp/ffuf.tar.gz && \
    tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf && \
    rm /tmp/ffuf.tar.gz

COPY . /app

RUN pip install --upgrade pip && pip install --no-cache-dir .

EXPOSE 8000

CMD ["python", "-m", "lattice_mind.api.serve_with_mcp"]
