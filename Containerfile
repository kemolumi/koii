FROM rust:1.95.0

WORKDIR /
COPY . .

RUN cargo build --release
RUN mv /target/release/koii /

EXPOSE 8340

CMD ["./koii", "secure"]
