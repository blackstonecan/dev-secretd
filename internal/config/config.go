// Package config reads /etc/secretd/config.json. The file holds no secrets.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

const DefaultPath = "/etc/secretd/config.json"

type Config struct {
	Socket     string `json:"socket"`      // Unix socket of the API
	ProxyAddr  string `json:"proxy_addr"`  // loopback address of the proxy
	StateDir   string `json:"state_dir"`   // store, state and audit log
	MasterCred string `json:"master_cred"` // systemd-creds file with the master key
	AllowUID   int    `json:"allow_uid"`   // the one user that may use the API
}

func Default() Config {
	return Config{
		Socket:     "/run/secretd/api.sock",
		ProxyAddr:  "127.0.0.1:7777",
		StateDir:   "/var/lib/secretd",
		MasterCred: "/etc/secretd/master.cred",
		AllowUID:   -1,
	}
}

// Load reads the config. Root always uses DefaultPath: an environment
// variable must not redirect a root command to other files.
func Load() (Config, error) {
	path := DefaultPath
	if p := os.Getenv("SECRETD_CONFIG"); p != "" && os.Geteuid() != 0 {
		path = p
	}
	return LoadFile(path)
}

func LoadFile(path string) (Config, error) {
	c := Default()
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("cannot read %s (is secretd installed?): %w", path, err)
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	host, _, err := net.SplitHostPort(c.ProxyAddr)
	if err != nil {
		return fmt.Errorf("proxy_addr: %w", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("proxy_addr must be a loopback IP, got %q", c.ProxyAddr)
	}
	if c.Socket == "" || c.StateDir == "" {
		return fmt.Errorf("socket and state_dir are required")
	}
	return nil
}
