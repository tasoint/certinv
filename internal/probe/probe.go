package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	certmeta "github.com/tasoint/certinv/internal/cert"
)

type Target struct {
	Hostname string
	Port     int
}

type Result struct {
	Target      Target
	Certificate certmeta.Metadata
	ProbedAt    time.Time
}

type Prober interface {
	Probe(ctx context.Context, target Target) (Result, error)
}

type TLSProber struct {
	dialer           *net.Dialer
	connectTimeout   time.Duration
	handshakeTimeout time.Duration
	now              func() time.Time
}

func NewTLSProber(connectTimeout, handshakeTimeout time.Duration) *TLSProber {
	return &TLSProber{
		dialer: &net.Dialer{
			Timeout: connectTimeout,
		},
		connectTimeout:   connectTimeout,
		handshakeTimeout: handshakeTimeout,
		now:              time.Now,
	}
}

func (p *TLSProber) Probe(ctx context.Context, target Target) (Result, error) {
	if target.Port == 0 {
		target.Port = 443
	}
	address := net.JoinHostPort(target.Hostname, strconv.Itoa(target.Port))
	dialer := p.dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: p.connectTimeout}
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return Result{}, fmt.Errorf("connect %s: %w", address, err)
	}
	defer rawConn.Close()

	if p.handshakeTimeout > 0 {
		if err := rawConn.SetDeadline(time.Now().Add(p.handshakeTimeout)); err != nil {
			return Result{}, fmt.Errorf("set TLS deadline for %s: %w", address, err)
		}
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         target.Hostname,
		InsecureSkipVerify: true,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return Result{}, fmt.Errorf("TLS handshake %s: %w", address, err)
	}

	state := tlsConn.ConnectionState()
	probedAt := p.now()
	metadata, err := certmeta.FromChain(state.PeerCertificates, target.Hostname, probedAt)
	if err != nil {
		return Result{}, fmt.Errorf("parse certificate metadata for %s: %w", address, err)
	}

	return Result{
		Target:      target,
		Certificate: metadata,
		ProbedAt:    probedAt,
	}, nil
}
