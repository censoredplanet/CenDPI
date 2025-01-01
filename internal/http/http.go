package http

import (
	"strings"
)

type HTTPConfig struct {
	Request            string
	Domain             string
	AllCapsHostDomain  bool
	AllLowerHostDomain bool
}

func BuildHTTPRequest(cfg *HTTPConfig) ([]byte, error) {
	hostDomain := cfg.Domain
	if cfg.AllCapsHostDomain {
		hostDomain = strings.ToUpper(hostDomain)
	} else if cfg.AllLowerHostDomain {
		hostDomain = strings.ToLower(hostDomain)
	}
	// replace ${} with cfg.Domain
	request := cfg.Request
	request = strings.Replace(request, "${}", hostDomain, 1)

	return []byte(request), nil
}
