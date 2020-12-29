// Package hmacsig implements an HMAC Signature Validation HTTP Middleware
// for use with the likes of GitHub Webhooks.
package hmacsig

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"net/http"
)

// Option sets an option of the passed hmacSig
type Option func(*hmacSig)

const (
	// GithubSignatureHeader is the default header used by GitHub for their
	// SHA-1 WebHook signatures
	GithubSignatureHeader = "X-Hub-Signature"

	// GithubSignatureHeader256 is the default header used by GitHub for their
	// SHA-256 WebHook signatures
	GithubSignatureHeader256 = "X-Hub-Signature-256"

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

	validator SignatureValidator
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

// OptionDefaultsSHA256 configures the HTTP Header and Validator used to the
// defaults used by GitHub for SHA256 validation
func OptionDefaultsSHA256(mux *hmacSig) {
	mux.header = GithubSignatureHeader256
	mux.validator = SHA256Validator
}

// OptionSignatureValidator configures the HMAC SignatureValidator
// validated against
func OptionSignatureValidator(validator SignatureValidator) Option {
	return func(mux *hmacSig) {
		mux.validator = validator
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

		validator: SHA1Validator,
	}

	for _, option := range options {
		option(sig)
	}

	return sig
}

// Handler256 provides HMAC signature validating middleware defaulting to SHA256.
//
// Handler256 is a convenience method which invokes Handler while including
// OptionDefaultsSHA256 as the first Option
func Handler256(h http.Handler, secret string, options ...Option) http.Handler {
	return Handler(h, secret, append([]Option{OptionDefaultsSHA256}, options...)...)
}

// SignatureValidator validates the body of a request against the requests
// signature and servers secret
type SignatureValidator func(body []byte, sig, secret string) bool

// SHA1Validator implements the interface SignatureValidator and
// SHA-1 HMAC validation
func SHA1Validator(body []byte, sig, secret string) bool {
	hash := hmac.New(sha1.New, []byte(secret))
	hash.Write(body)

	ehash := hash.Sum(nil)
	esig := "sha1=" + hex.EncodeToString(ehash)

	return hmac.Equal([]byte(esig), []byte(sig))
}

// SHA256Validator implements the interface SignatureValidator and
// SHA-256 HMAC validation
func SHA256Validator(body []byte, sig, secret string) bool {
	hash := hmac.New(sha256.New, []byte(secret))
	hash.Write(body)

	ehash := hash.Sum(nil)
	esig := "sha256=" + hex.EncodeToString(ehash)

	return hmac.Equal([]byte(esig), []byte(sig))
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

	if !xh.validator(b, xSig, xh.secret) {
		xh.verifyFailedHandler.ServeHTTP(w, r)
		return
	}

	r.Body.Close()
	r.Body = ioutil.NopCloser(bytes.NewBuffer(b))

	xh.h.ServeHTTP(w, r)
}
