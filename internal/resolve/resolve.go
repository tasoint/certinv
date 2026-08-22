package resolve

import (
	"context"
	"fmt"
	"net"
)

type Result struct {
	Hostname  string
	Addresses []string
	Resolved  bool
}

type Resolver interface {
	Resolve(ctx context.Context, hostname string) (Result, error)
}

type NetResolver struct {
	resolver *net.Resolver
}

func NewNetResolver(resolver *net.Resolver) *NetResolver {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &NetResolver{resolver: resolver}
}

func (r *NetResolver) Resolve(ctx context.Context, hostname string) (Result, error) {
	ips, err := r.resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return Result{Hostname: hostname, Resolved: false}, nil
	}

	addresses := make([]string, 0, len(ips))
	for _, ip := range ips {
		addresses = append(addresses, ip.IP.String())
	}
	if len(addresses) == 0 {
		return Result{Hostname: hostname, Resolved: false}, nil
	}
	return Result{Hostname: hostname, Addresses: addresses, Resolved: true}, nil
}

func RequireResolved(result Result) error {
	if !result.Resolved {
		return fmt.Errorf("host %q did not resolve", result.Hostname)
	}
	return nil
}
