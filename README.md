# hmacsig

[![Build Status](https://travis-ci.org/donatj/hmacsig.svg?branch=master)](https://travis-ci.org/donatj/hmacsig)
[![GoDoc](https://godoc.org/github.com/donatj/hmacsig?status.svg)](https://godoc.org/github.com/donatj/hmacsig)
[![Go Report Card](https://goreportcard.com/badge/github.com/donatj/hmacsig)](https://goreportcard.com/report/github.com/donatj/hmacsig)

HMAC Signature Validation Middleware (like GitHub Webhooks Uses)

### Example

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

	s := hmacsig.Handler(h, "supersecret")

	err := http.ListenAndServe(":8080", s)
	if err != nil {
		log.Fatal(err)
	}
}
```
