FROM alpine:3.4
MAINTAINER Virgil <support@VirgilSecurity.com>
RUN apk add --update ca-certificates
ARG VERSION=unkown
LABEL version=$VERSION
ADD virgil-auth .
ENV PORT 8080
EXPOSE 8080
ENTRYPOINT ["/virgil-auth"]
