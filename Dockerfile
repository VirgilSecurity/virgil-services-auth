FROM scratch
ADD main /
EXPOSE 8080
ENTRYPOINT ["/main"]
