# hmacsig

[![Build Status](https://travis-ci.org/donatj/hmacsig.svg?branch=master)](https://travis-ci.org/donatj/hmacsig)
[![GoDoc](https://godoc.org/github.com/donatj/hmacsig?status.svg)](https://godoc.org/github.com/donatj/hmacsig)
[![Go Report Card](https://goreportcard.com/badge/github.com/donatj/hmacsig)](https://goreportcard.com/report/github.com/donatj/hmacsig)

HMAC Signature Validation Middleware (like GitHub Webhooks Uses)

Supports SHA-1 validation via `hmacsig.Handler` and SHA-256 validation via `hmacsig.Handler256`

## Example

```golang
package main

import (
	"log"
	"net/http"

	"github.com/donatj/hmacsig"
)

func main() {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("success"))
	})

	s := hmacsig.Handler256(h, "supersecret")

	err := http.ListenAndServe(":8080", s)
	if err != nil {
		log.Fatal(err)
	}
}
```
