package hmacsig

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInvalidHeaders(t *testing.T) {
	tt := []struct {
		reqHeader string
		secret    string
		msg       string
	}{
		{"", "", MsgMissingSignature},
		{"invalid", "xasd", MsgFailedHMAC},
	}

	for _, tc := range tt {
		req, _ := http.NewRequest("POST", "localhost", bytes.NewReader([]byte{}))
		req.Header.Set(GithubSignatureHeader, tc.reqHeader)
		rec := httptest.NewRecorder()

		x := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("should not be executed")
		})

		xhs := Handler(x, tc.secret)
		xhs.ServeHTTP(rec, req)

		res := rec.Result()

		if res.StatusCode != http.StatusForbidden {
			t.Errorf("expected status Forbidden; got %v", res.Status)
		}

		body, _ := ioutil.ReadAll(res.Body)
		sbody := strings.TrimSpace(string(body))
		if sbody != tc.msg {
			t.Errorf("expected message '%v'; got '%v'", tc.msg, sbody)
		}
	}
}

func TestValidHMAC(t *testing.T) {
	tt := []struct {
		reqHeader string
		secret    string
		body      string
		msg       string
	}{
		{"sha1=0de7dbe42dfef6ed31d9d0d4374c962209e5339c", "supersecret", "This is the body of the request", "ok"},
		{"sha1=587eed5390987ba9ee890cafa946eed9dacf2e52", "ThisKeyIsAGreatSecretYouShouldNotUseIt", "This is a more different body", "even more ok"},
	}

	for _, tc := range tt {
		req, _ := http.NewRequest("POST", "localhost", bytes.NewReader([]byte(tc.body)))
		req.Header.Set(GithubSignatureHeader, tc.reqHeader)
		rec := httptest.NewRecorder()

		x := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}

			bs := string(b)
			if bs != tc.body {
				t.Errorf("expected read '%v'; got '%v'", tc.body, bs)
			}

			w.Write([]byte(tc.msg))
		})

		xhs := Handler(x, tc.secret)
		xhs.ServeHTTP(rec, req)

		res := rec.Result()

		if res.StatusCode != http.StatusOK {
			t.Errorf("expected status OK; got %v", res.Status)
		}

		body, _ := ioutil.ReadAll(res.Body)
		sbody := strings.TrimSpace(string(body))
		if sbody != tc.msg {
			t.Errorf("expected message '%v'; got '%v'", tc.msg, sbody)
		}
	}
}
