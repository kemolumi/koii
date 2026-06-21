FROM rust:1.95.0

WORKDIR /
COPY . .

RUN rm -rf .cargo

RUN cargo build --release
RUN mv /target/release/koii /
RUN rm -rf /target

EXPOSE 8340

CMD ["./koii", "secure"]
