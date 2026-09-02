FROM debian:bookworm-slim AS build

ARG OPENSSL_VERSION=3.5.8
ARG NGINX_VERSION=1.30.4
ARG NGINX_SHA256=4261dc90e9e47c1c4041276e9aaa3d48ebe2e664f728e14fa95ae6c67d57a08b

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl libpcre2-dev perl zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN curl -fsSLO "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
    && curl -fsSLO "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz.sha256" \
    && sha256sum -c "openssl-${OPENSSL_VERSION}.tar.gz.sha256" \
    && tar -xzf "openssl-${OPENSSL_VERSION}.tar.gz"

RUN cd "openssl-${OPENSSL_VERSION}" \
    && ./Configure --prefix=/opt/openssl --openssldir=/opt/openssl shared \
    && make -j2 \
    && make install_sw

RUN curl -fsSLO "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
    && echo "${NGINX_SHA256}  nginx-${NGINX_VERSION}.tar.gz" | sha256sum -c - \
    && tar -xzf "nginx-${NGINX_VERSION}.tar.gz" \
    && cd "nginx-${NGINX_VERSION}" \
    && ./configure --prefix=/opt/nginx --with-http_ssl_module --with-openssl="/build/openssl-${OPENSSL_VERSION}" --with-openssl-opt="no-tests" \
    && make -j2 \
    && make install

# install_sw deliberately omits the CLI configuration file. The protocol lab
# exercises provider-backed ML-KEM/ML-DSA operations, so install it explicitly.
RUN cp "openssl-${OPENSSL_VERSION}/apps/openssl.cnf" /opt/openssl/openssl.cnf

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libpcre2-8-0 zlib1g \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/openssl /opt/openssl
COPY --from=build /opt/nginx /opt/nginx
COPY entrypoint.sh /usr/local/bin/pqc-lab-entrypoint
COPY nginx.template.conf /opt/nginx/conf/nginx.template.conf
RUN chmod 0755 /usr/local/bin/pqc-lab-entrypoint
ENV PATH="/opt/openssl/bin:/opt/nginx/sbin:${PATH}" \
    LD_LIBRARY_PATH="/opt/openssl/lib64:/opt/openssl/lib" \
    OPENSSL_CONF="/opt/openssl/openssl.cnf"
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/pqc-lab-entrypoint"]
