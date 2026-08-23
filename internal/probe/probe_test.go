package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTLSProberHTTPCheck(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer server.Close()
	port := server.Listener.Addr().(*net.TCPAddr).Port

	prober := NewTLSProber(time.Second, time.Second, true)
	result, err := prober.Probe(context.Background(), Target{Hostname: "127.0.0.1", Port: port})
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if result.HTTPStatus != http.StatusTeapot {
		t.Fatalf("HTTPStatus = %d, want %d", result.HTTPStatus, http.StatusTeapot)
	}
}

func TestTLSProberHTTPCheckDisabled(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP request should not be made when disabled")
	}))
	defer server.Close()
	port := server.Listener.Addr().(*net.TCPAddr).Port

	prober := NewTLSProber(time.Second, time.Second)
	result, err := prober.Probe(context.Background(), Target{Hostname: "127.0.0.1", Port: port})
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if result.HTTPStatus != 0 {
		t.Fatalf("HTTPStatus = %d, want 0", result.HTTPStatus)
	}
}
