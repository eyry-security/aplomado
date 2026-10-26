FROM python:3.12-slim

# The sandbox image is deliberately self-contained: the bug-hunter binaries
# and nuclei templates are installed at build time so scans never need an
# internet bootstrap or a relaxed command policy.
ARG NUCLEI_VERSION=3.3.9
ARG FFUF_VERSION=2.1.0
ARG DALFOX_VERSION=3.2.4
ARG KATANA_VERSION=1.1.0
ARG SQLMAP_VERSION=1.10.10

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash ca-certificates curl dnsutils openssl unzip tar \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    tmp="$(mktemp -d)"; \
    curl -fsSL -o "$tmp/nuclei.zip" \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"; \
    unzip -q "$tmp/nuclei.zip" -d "$tmp/nuclei"; \
    install -m 0755 "$tmp/nuclei/nuclei" /usr/local/bin/nuclei; \
    curl -fsSL -o "$tmp/katana.zip" \
      "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip"; \
    unzip -q "$tmp/katana.zip" -d "$tmp/katana"; \
    install -m 0755 "$tmp/katana/katana" /usr/local/bin/katana; \
    curl -fsSL -o "$tmp/ffuf.tar.gz" \
      "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz"; \
    tar -xzf "$tmp/ffuf.tar.gz" -C "$tmp"; \
    install -m 0755 "$tmp/ffuf" /usr/local/bin/ffuf; \
    curl -fsSL -o "$tmp/dalfox.tar.gz" \
      "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox-v${DALFOX_VERSION}-linux-x86_64.tar.gz"; \
    tar -xzf "$tmp/dalfox.tar.gz" -C "$tmp"; \
    install -m 0755 "$tmp/dalfox-v${DALFOX_VERSION}-linux-x86_64/dalfox" /usr/local/bin/dalfox; \
    rm -rf "$tmp"

RUN pip install --no-cache-dir "sqlmap==${SQLMAP_VERSION}" \
    && mkdir -p /opt/nuclei-templates \
    && nuclei -update-templates -ud /opt/nuclei-templates -silent \
    && chmod -R a+rX /opt/nuclei-templates \
    && test -d /opt/nuclei-templates/http/cves \
    && test -d /opt/nuclei-templates/http/exposures \
    && test -d /opt/nuclei-templates/http/misconfiguration \
    && test -d /opt/nuclei-templates/http/takeovers

RUN useradd --create-home --uid 10001 scanner \
    && mkdir /work && chown scanner:scanner /work

USER scanner
WORKDIR /work
CMD ["sleep", "infinity"]
