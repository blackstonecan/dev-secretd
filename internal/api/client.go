package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Client talks to secretd over its Unix socket.
type Client struct {
	http *http.Client
	hold *http.Client // no overall timeout: the response body stays open for a run
}

func NewClient(socket string) *Client {
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}
	return &Client{
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{DialContext: dial},
		},
		hold: &http.Client{
			Transport: &http.Transport{DialContext: dial, ResponseHeaderTimeout: 30 * time.Second},
		},
	}
}

func (c *Client) Set(req SetRequest) error {
	return c.do("POST", "/v1/set", req, nil)
}

func (c *Client) List(project string) ([]Info, error) {
	var out []Info
	err := c.do("GET", "/v1/list?project="+url.QueryEscape(project), nil, &out)
	return out, err
}

// Get returns a public value of the project, or of the user scope.
func (c *Client) Get(project, name string) (Info, error) {
	var out Info
	err := c.do("GET", "/v1/get?project="+url.QueryEscape(project)+"&name="+url.QueryEscape(name), nil, &out)
	return out, err
}

func (c *Client) Resolve(req ResolveRequest) ([]Resolved, error) {
	var out []Resolved
	err := c.do("POST", "/v1/resolve", req, &out)
	return out, err
}

// ResolveHold is Resolve for a run that holds the connection: keys for
// run_key secrets live until the returned Closer is closed (or the process
// dies). The caller must close it after the run.
func (c *Client) ResolveHold(req ResolveRequest) ([]Resolved, io.Closer, error) {
	req.Hold = true
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}
	hr, err := http.NewRequest("POST", "http://secretd/v1/resolve", bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}
	hr.Header.Set("Content-Type", "application/json")
	resp, err := c.hold.Do(hr)
	if err != nil {
		return nil, nil, wrapDial(err)
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		return nil, nil, statusError(resp)
	}
	var out []Resolved
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		resp.Body.Close()
		return nil, nil, err
	}
	return out, resp.Body, nil
}

// OAuthExchange finishes a consent: the daemon exchanges the code and stores
// the refresh token. The exchange can take a while at the token endpoint.
func (c *Client) OAuthExchange(req OAuthExchangeRequest) (OAuthExchangeResult, error) {
	var out OAuthExchangeResult
	err := c.do("POST", "/v1/oauth/exchange", req, &out)
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
		return wrapDial(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return statusError(resp)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func wrapDial(err error) error {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return fmt.Errorf("cannot reach secretd (is it running?): %w", err)
	}
	return err
}

func statusError(resp *http.Response) error {
	var e errorBody
	if json.NewDecoder(resp.Body).Decode(&e) == nil && e.Error != "" {
		return errors.New(e.Error)
	}
	return fmt.Errorf("secretd: HTTP %d", resp.StatusCode)
}
