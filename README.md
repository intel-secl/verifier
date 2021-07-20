# ISecL Verifier Library

This library verifies policies defined by a flavor against a manifest, generating a trust report that indicates whether or not to trust subject.

## System Requirements
- RHEL 8.1
- Epel 8 Repo
- Proxy settings if applicable

## Software requirements
- git
- `go` version 1.14.4

# Step By Step Build Instructions

## Install required shell commands

### Install `go` version 1.14.4
The `Verifier` requires Go version 1.14.4 that has support for `go modules`. The build was validated with the latest version 1.14.4 of `go`. It is recommended that you use 1.14.4 version of `go`. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.14.4.linux-amd64.tar.gz
tar -xzf go1.14.4.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

## Build Verifier

- Git clone the Verifier
- Run scripts to build the Verifier

```shell
git clone https://github.com/intel-secl/verifier.git
cd verifier
```
```shell
go build ./...
```

# Links
https://01.org/intel-secl/
