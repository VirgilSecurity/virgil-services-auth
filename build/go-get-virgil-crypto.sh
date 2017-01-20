#!/bin/bash

echo "Getting virgil-crypto-go dependencies"
go get -v -u ./...
pwd
# until crypto-go wrapper is not published
cd $GOPATH
mkdir -p $GOPATH/src/gopkg.in/virgilsecurity/virgil-crypto-go.v4
wget https://cdn.virgilsecurity.com/crypto-go/virgil-crypto-2.0.4-go-linux-x86_64.tgz
tar -xvf virgil-crypto-2.0.4-go-linux-x86_64.tgz --strip-components=1 -C $GOPATH/src/gopkg.in/virgilsecurity/virgil-crypto-go.v4/
cd -
echo "listing: $GOPATH/src/gopkg.in/virgilsecurity/virgil-crypto-go.v4/"
ls -l $GOPATH/src/gopkg.in/virgilsecurity/virgil-crypto-go.v4/
gcc -v
