FROM debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tor \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o debian-tor -g debian-tor -m 0700 /var/lib/tor

COPY --chmod=0555 tor/entrypoint.sh /usr/local/bin/argus-tor-entrypoint

USER debian-tor
EXPOSE 9050 9051
ENTRYPOINT ["/usr/local/bin/argus-tor-entrypoint"]
