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

// Option sets an option of the passed JqMux
type Option func(*hmacSig)

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

	missingSignatureHandler http.Handler
	verifyFailedHandler     http.Handler
}

// OptionHeader configures the HTTP Header to read for the signature
func OptionHeader(header string) Option {
	return func(mux *hmacSig) {
		mux.header = header
	}
}

// OptionMissingSignatureHandler configures the http.Handler called on missing signature
func OptionMissingSignatureHandler(handler http.Handler) Option {
	return func(mux *hmacSig) {
		mux.missingSignatureHandler = handler
	}
}

// OptionVerifyFailedHandler configures the http.Handler called on
// HMAC verification failure
func OptionVerifyFailedHandler(handler http.Handler) Option {
	return func(mux *hmacSig) {
		mux.verifyFailedHandler = handler
	}
}

// DefaultMissingSignatureHandler is the default response to a missing signature
func DefaultMissingSignatureHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, MsgMissingSignature, http.StatusForbidden)
}

// DefaultVerifyFailedHandler is the default response to HMAC verification failing
func DefaultVerifyFailedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, MsgFailedHMAC, http.StatusForbidden)
}

// Handler provides HMAC signature validating middleware.
//
// see: https://developer.github.com/webhooks/securing/
//
// If no options.Header is provided, GithubSignatureHeader will be used.
func Handler(h http.Handler, secret string, options ...Option) http.Handler {
	sig := &hmacSig{
		h:      h,
		secret: secret,
		header: GithubSignatureHeader,

		missingSignatureHandler: http.HandlerFunc(DefaultMissingSignatureHandler),
		verifyFailedHandler:     http.HandlerFunc(DefaultVerifyFailedHandler),
	}

	for _, option := range options {
		option(sig)
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
		xh.missingSignatureHandler.ServeHTTP(w, r)
		return
	}

	hash := hmac.New(sha1.New, []byte(xh.secret))
	hash.Write(b)

	ehash := hash.Sum(nil)
	esig := "sha1=" + hex.EncodeToString(ehash)

	if !hmac.Equal([]byte(esig), []byte(xSig)) {
		xh.verifyFailedHandler.ServeHTTP(w, r)
		return
	}

	r.Body.Close()
	r.Body = ioutil.NopCloser(bytes.NewBuffer(b))

	xh.h.ServeHTTP(w, r)
}
