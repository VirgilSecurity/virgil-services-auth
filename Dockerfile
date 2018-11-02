FROM alpine:latest as build
RUN  apk add --no-cache ca-certificates

FROM scratch
MAINTAINER Virgil <support@VirgilSecurity.com>
arg VERSION=unkown
LABEL version=$VERSION
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /etc/passwd /etc/passwd
ADD virgil-auth .
ENV PORT 8080
EXPOSE 8080
USER nobody
ENTRYPOINT ["/virgil-auth"]
