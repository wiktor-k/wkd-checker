FROM rust

RUN apt-get update && apt-get install --assume-yes clang

COPY ./ ./

RUN cargo build --release

EXPOSE 3000

CMD ["/target/release/wkd-checker"]
