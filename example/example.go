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
