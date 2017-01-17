#!/bin/bash

echo "Getting virgil-crypto-go dependencies"
go get -v ./...
pwd
# until crypto-go wrapper is not published
cd $GOPATH
mkdir -p $GOPATH/src/gopkg.in/virgilsecurity/virgil-crypto-go.v4
wget cdn.VirgilSecurity.com/crypto-go/crypto-go-linux.tgz
tar -xvf crypto-go-linux.tgz --strip-components=1 -C $GOPATH/src/gopkg.in/virgilsecurity/virgil-crypto-go.v4/
cd -
echo "listing: $GOPATH/src/gopkg.in/virgilsecurity/virgil-crypto-go.v4/"
ls -l $GOPATH/src/gopkg.in/virgilsecurity/virgil-crypto-go.v4/
gcc -v
