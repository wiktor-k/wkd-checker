FROM rust as cargo-build

RUN apt-get update && apt-get install --assume-yes clang

WORKDIR /usr/src/app
COPY Cargo.lock Cargo.toml ./
RUN mkdir src
RUN echo "fn main() { }" > src/main.rs
RUN cargo build --release

COPY ./src src
RUN cargo build --release

FROM debian:10-slim

COPY --from=cargo-build /usr/src/app/target/release/wkd-checker /wkd-checker
COPY --from=cargo-build /usr/lib/x86_64-linux-gnu/libssl.so.1.1 /usr/lib/
COPY --from=cargo-build /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 /usr/lib/

COPY --from=cargo-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

EXPOSE 3000

CMD ["/wkd-checker"]
