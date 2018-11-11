// Package hmacsig implements an HMAC Signature Validation HTTP Middleware
// for use with the likes of GitHub Webhooks.
package hmacsig

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"io/ioutil"
	"net/http"
)

const (
	// GithubSignatureHeader is the default header used by GitHub for their
	// WebHook signatures
	GithubSignatureHeader = "X-Hub-Signature"

	// MsgMissingSignature is the message returned in the body when the
	// Signature was missing from the request
	MsgMissingSignature = "Missing required header for HMAC verification"

	// MsgFailedHMAC is the message returned in the body when the HMAC did not
	// Validate as Anticpated.
	MsgFailedHMAC = "HMAC verification failed"
)

type hmacSig struct {
	h http.Handler

	secret string
	header string
}

// Options are the available configuration options for HMACSig
type Options struct {
	// The HTTP Header to read for the signature
	Header string
}

// Handler provides HMAC signature validating middleware.
//
// see: https://developer.github.com/webhooks/securing/
//
// If no options.Header is provided, GithubSignatureHeader will be used.
func Handler(h http.Handler, secret string, options Options) http.Handler {
	sig := &hmacSig{
		h:      h,
		secret: secret,
		header: GithubSignatureHeader,
	}

	if options.Header != "" {
		sig.header = options.Header
	}

	return sig
}

func (xh *hmacSig) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	xSig := r.Header.Get(xh.header)

	if xSig == "" {
		http.Error(w, MsgMissingSignature, http.StatusForbidden)
		return
	}

	hash := hmac.New(sha1.New, []byte(xh.secret))
	hash.Write(b)

	ehash := hash.Sum(nil)
	esig := "sha1=" + hex.EncodeToString(ehash)

	if !hmac.Equal([]byte(esig), []byte(xSig)) {
		http.Error(w, MsgFailedHMAC, http.StatusForbidden)
		return
	}

	r.Body.Close()
	r.Body = ioutil.NopCloser(bytes.NewBuffer(b))

	xh.h.ServeHTTP(w, r)
}
