FROM python:3.12-slim

ARG NUCLEI_VERSION=3.4.10
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl nmap unzip \
    && curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip nuclei -d /usr/local/bin \
    && rm -rf /var/lib/apt/lists/* /tmp/nuclei.zip

RUN useradd --create-home --uid 10001 scanner && mkdir /work && chown scanner:scanner /work
USER scanner
WORKDIR /work
CMD ["sleep", "infinity"]
