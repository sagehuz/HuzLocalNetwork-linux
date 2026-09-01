package scanner

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed oui.txt
var ouiRaw string

var (
	ouiOnce sync.Once
	ouiMap  map[string]string
)

func loadOUI() {
	ouiMap = make(map[string]string, 256)
	for _, line := range strings.Split(ouiRaw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, "\t", 2)
		if len(fields) != 2 {
			continue
		}
		prefix := normalizeMACPrefix(fields[0])
		if prefix == "" {
			continue
		}
		ouiMap[prefix] = strings.TrimSpace(fields[1])
	}
}

// LookupVendor returns the manufacturer name for a MAC address, or "" if
// unknown. Lookup is based on the first 3 octets (the OUI).
func LookupVendor(mac string) string {
	ouiOnce.Do(loadOUI)
	prefix := normalizeMACPrefix(mac)
	if prefix == "" {
		return ""
	}
	return ouiMap[prefix]
}

// normalizeMACPrefix extracts the first 6 hex digits (OUI) from a MAC
// address or raw prefix string, uppercased and without separators.
func normalizeMACPrefix(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			b.WriteRune(r)
		}
		if b.Len() >= 6 {
			break
		}
	}
	if b.Len() < 6 {
		return ""
	}
	return strings.ToUpper(b.String())
}
