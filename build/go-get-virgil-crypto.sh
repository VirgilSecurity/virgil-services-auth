#!/bin/bash

echo "Getting virgil-crypto-go dependencies"
go get -v ./...
pwd
# until crypto-go wrapper is not published
cd $GOPATH
mkdir -p $GOPATH/src/github.com/VirgilSecurity/virgil-crypto-go
wget cdn.virgilsecurity.com/crypto-go/crypto-go-linux.tgz
tar -xvf crypto-go-linux.tgz --strip-components=1 -C $GOPATH/src/github.com/VirgilSecurity/virgil-crypto-go/
cd -
echo "listing: $GOPATH/src/github.com/VirgilSecurity/virgil-crypto-go/"
ls -l $GOPATH/src/github.com/VirgilSecurity/virgil-crypto-go/
gcc -v
