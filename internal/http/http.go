package http

import (
    "fmt"
)

type HTTPConfig struct {
    Version string
    Method  string
    Path    string
    Domain  string
}


func BuildHTTPRequest(cfg *HTTPConfig) ([]byte, error) {
    // Some defaults if fields are empty
    if cfg.Version == "" {
        cfg.Version = "HTTP/1.1"
    }
    if cfg.Method == "" {
        cfg.Method = "GET"
    }
    if cfg.Path == "" {
        cfg.Path = "/"
    }

    request := fmt.Sprintf(
        "%s %s %s\r\nHost: %s\r\n\r\n",
        cfg.Method,
        cfg.Path,
        cfg.Version,
        cfg.Domain,
    )
    return []byte(request), nil
}
