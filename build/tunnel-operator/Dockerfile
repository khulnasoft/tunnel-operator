FROM alpine:3.20.3

RUN apk update

RUN apk upgrade

RUN adduser -u 10000 -D -g '' tunneloperator tunneloperator

COPY tunnel-operator /usr/local/bin/tunnel-operator

USER 10000

ENTRYPOINT ["tunnel-operator"]
