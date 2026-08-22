package zonefile

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/tasoint/certinv/internal/discover"
)

type Source struct {
	files []string
}

func New(files []string) *Source {
	return &Source{files: files}
}

func (s *Source) Name() string {
	return discover.SourceZone
}

func (s *Source) Discover(ctx context.Context, apexes []string) ([]discover.Host, error) {
	var groups [][]discover.Host
	for _, path := range s.files {
		hosts, err := s.discoverFile(ctx, path, apexes)
		if err != nil {
			return nil, err
		}
		groups = append(groups, hosts)
	}
	return discover.Merge(groups...), nil
}

func (s *Source) discoverFile(ctx context.Context, path string, apexes []string) ([]discover.Host, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open zone file %q: %w", path, err)
	}
	defer file.Close()

	parser := parser{}
	var hosts []discover.Host
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lineNo++
		host, ok, err := parser.parseLine(scanner.Text(), apexes)
		if err != nil {
			return nil, fmt.Errorf("parse zone file %q line %d: %w", path, lineNo, err)
		}
		if ok {
			hosts = append(hosts, host)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read zone file %q: %w", path, err)
	}
	return discover.Merge(hosts), nil
}

type parser struct {
	origin    string
	lastOwner string
}

func (p *parser) parseLine(line string, apexes []string) (discover.Host, bool, error) {
	line = stripComment(line)
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return discover.Host{}, false, nil
	}
	if strings.EqualFold(fields[0], "$ORIGIN") {
		if len(fields) < 2 {
			return discover.Host{}, false, fmt.Errorf("$ORIGIN requires a value")
		}
		p.origin = discover.NormalizeHostname(fields[1])
		return discover.Host{}, false, nil
	}
	if strings.HasPrefix(fields[0], "$") {
		return discover.Host{}, false, nil
	}

	owner, recordType := p.ownerAndType(fields)
	if recordType == "" {
		return discover.Host{}, false, nil
	}
	p.lastOwner = owner

	hostname := p.absoluteName(owner)
	apex, ok := discover.ApexFor(hostname, apexes)
	if !ok {
		return discover.Host{}, false, nil
	}
	return discover.Host{
		Hostname: hostname,
		Port:     discover.DefaultPort,
		Apex:     apex,
		Source:   discover.SourceZone,
	}, true, nil
}

func (p *parser) ownerAndType(fields []string) (string, string) {
	for i, field := range fields {
		upper := strings.ToUpper(field)
		switch upper {
		case "A", "AAAA", "CNAME":
			if i == 0 {
				return p.lastOwner, upper
			}
			owner := fields[0]
			if isTTL(owner) || isClass(owner) {
				return p.lastOwner, upper
			}
			return owner, upper
		}
	}
	return "", ""
}

func (p *parser) absoluteName(name string) string {
	raw := strings.TrimSpace(name)
	name = discover.NormalizeHostname(raw)
	switch {
	case name == "":
		return ""
	case name == "@":
		return p.origin
	case strings.HasSuffix(raw, "."):
		return discover.NormalizeHostname(name)
	case p.origin != "":
		return discover.NormalizeHostname(name + "." + p.origin)
	default:
		return name
	}
}

func stripComment(line string) string {
	if i := strings.Index(line, ";"); i >= 0 {
		return line[:i]
	}
	return line
}

func isClass(value string) bool {
	switch strings.ToUpper(value) {
	case "IN", "CH", "HS":
		return true
	default:
		return false
	}
}

func isTTL(value string) bool {
	_, err := strconv.Atoi(value)
	return err == nil
}
