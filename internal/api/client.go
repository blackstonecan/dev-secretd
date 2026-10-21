package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Client talks to secretd over its Unix socket.
type Client struct {
	http *http.Client
}

func NewClient(socket string) *Client {
	return &Client{http: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}}
}

func (c *Client) Set(req SetRequest) error {
	return c.do("POST", "/v1/set", req, nil)
}

func (c *Client) List(project string) ([]Info, error) {
	var out []Info
	err := c.do("GET", "/v1/list?project="+url.QueryEscape(project), nil, &out)
	return out, err
}

func (c *Client) Resolve(req ResolveRequest) ([]Resolved, error) {
	var out []Resolved
	err := c.do("POST", "/v1/resolve", req, &out)
	return out, err
}

func (c *Client) Lock(project string, locked bool) error {
	path := "/v1/unlock"
	if locked {
		path = "/v1/lock"
	}
	return c.do("POST", path, ProjectRequest{Project: project}, nil)
}

func (c *Client) Status() (Status, error) {
	var out Status
	err := c.do("GET", "/v1/status", nil, &out)
	return out, err
}

func (c *Client) do(method, path string, in, out any) error {
	var body *bytes.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	} else {
		body = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, "http://secretd"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			return fmt.Errorf("cannot reach secretd (is it running?): %w", err)
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e errorBody
		if json.NewDecoder(resp.Body).Decode(&e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("secretd: HTTP %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
