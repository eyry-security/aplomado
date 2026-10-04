FROM python:3.12-slim

# Common recon tools available inside the sandbox.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash ca-certificates curl dnsutils openssl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 scanner \
    && mkdir /work && chown scanner:scanner /work

USER scanner
WORKDIR /work
CMD ["sleep", "infinity"]
