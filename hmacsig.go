package xhubsig

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"io/ioutil"
	"log"
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

// HMACSigOptions are the availible configuration options for HMACSig
type HMACSigOptions struct {
	Header string
}

// HMACSig provides HMAC signature validating middleware.
//
// see: https://developer.github.com/webhooks/securing/
func HMACSig(h http.Handler, secret string, options HMACSigOptions) http.Handler {
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
	log.Println(esig, xSig)
	if !hmac.Equal([]byte(esig), []byte(xSig)) {
		http.Error(w, MsgFailedHMAC, http.StatusForbidden)
		return
	}

	xh.h.ServeHTTP(w, r)
}
