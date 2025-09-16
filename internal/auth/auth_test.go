package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestApiKey(t *testing.T) {
	empty := http.Header{}
	str, err := GetAPIKey(empty)
	if len(str) > 0 || err == nil {
		t.Fatalf("expected: %v and empty string, got %v and %s", ErrNoAuthHeaderIncluded, err, str)
	}

	nothing := http.Header{}
	nothing.Add("None", "Fake val")
	str, err = GetAPIKey(nothing)
	if len(str) > 0 || err == nil {
		t.Fatalf("expected: %v and empty string, got %v and %s", ErrNoAuthHeaderIncluded, err, str)
	}

	bad := http.Header{}
	bad.Add("Authorization", "fakekey")
	str, err = GetAPIKey(bad)
	testerr := errors.New("malformed authorization header")
	if len(str) > 0 || err == nil {
		t.Fatalf("expected: %v and empty string, got %v and %s", testerr, err, str)
	}

	good := http.Header{}
	good.Add("Authorization", "ApiKey fakekey")
	str, err = GetAPIKey(good)
	if str != "fakekey" || err != nil {
		t.Fatalf("expected: no error and \"fakekey\", got %v and %s", err, str)
	}
}
