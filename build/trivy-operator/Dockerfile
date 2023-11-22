FROM alpine:3.18.0
RUN apk update && apk add --upgrade libcrypto3 libssl3

RUN adduser -u 10000 -D -g '' tunneloperator tunneloperator

COPY tunnel-operator /usr/local/bin/tunnel-operator

USER 10000

ENTRYPOINT ["tunnel-operator"]
