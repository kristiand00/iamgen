FROM alpine:latest

RUN apk --no-cache add ca-certificates

COPY iamgen /usr/local/bin/iamgen

ENTRYPOINT ["/usr/local/bin/iamgen"]

