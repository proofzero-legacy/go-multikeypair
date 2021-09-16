# go-multikeypair

[![Go Reference](https://pkg.go.dev/badge/github.com/proofzero/go-multikeypair.svg)](https://pkg.go.dev/github.com/proofzero/go-multikeypair)
[![Go](https://img.shields.io/github/go-mod/go-version/proofzero/go-multikeypair)](https://golang.org/dl/)
[![Go Report Card](https://goreportcard.com/badge/github.com/proofzero/go-multikeypair)](https://goreportcard.com/report/github.com/proofzero/go-multikeypair)
![build](https://github.com/proofzero/go-multikeypair/actions/workflows/build.yaml/badge.svg)
![matrix](https://img.shields.io/matrix/lobby:matrix.kubelt.com?label=matrix&server_fqdn=matrix.kubelt.com)
[![Slack](https://img.shields.io/badge/slack-@kubelt-FD4E83.svg)](https://kubelt.slack.com)

A multiformats-inspired module for encoding cryptographic keypairs.

# Install

At a shell within your go module:

```bash
go get github.com/proofzero/go-multikeypair
```

# Build Instructions

```bash
go build
```

# Testing

```bash
go test
```

# Usage

Pseudo-golang for excercising the Encode and Decode API for a given hardcoded
keypair of a given crypto algorithm:

```golang
// Keys:
private := []byte("Wn3Sf5Ke/3:PA:Tm{KCf59Wg6j%/g*#d")
public := []byte("cv-sB6?r*RW8vP5TuMSv_wvw#dV4nUP!@y%u@pmK!P-S2gYVLve!PfdC#kew5Q7U")

// Cypher:
code := multikeypair.ED_25519
name := multikeypair.Codes[ED_25519]

// Encode:
mk, err := multikeypair.Encode(private, public, code)
if err != nil {
    panic(err)
}

// Decode:
kp, err := multikeypair.Decode(mk)
if err != nil {
    panic(err)
}
```

Documentation is inline with code as comments. See tests in `keypair_test.go`.

