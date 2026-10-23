// secretd is the daemon. It runs as its own system user (devsecrets), holds
// the encrypted store, serves the API on a Unix socket and the proxy on a
// loopback port.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/blackstonecan/dev-secretd/internal/api"
	"github.com/blackstonecan/dev-secretd/internal/config"
	"github.com/blackstonecan/dev-secretd/internal/proxy"
	"github.com/blackstonecan/dev-secretd/internal/state"
	"github.com/blackstonecan/dev-secretd/internal/store"
)

func main() {
	cfgPath := flag.String("config", config.DefaultPath, "config file")
	keyFile := flag.String("master-key-file", "", "master key file (tests only; systemd gives the key otherwise)")
	flag.Parse()
	log.SetFlags(0)

	cfg, err := config.LoadFile(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	if cfg.AllowUID < 0 {
		log.Fatal("allow_uid is not set in the config")
	}
	key, err := config.DaemonKey(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	s, err := store.Open(cfg.StateDir, key)
	if err != nil {
		log.Fatal(err)
	}
	// Fail at start, not at the first request, if the key does not match.
	if _, err := s.List(""); err != nil {
		log.Fatal(err)
	}
	st, err := state.Load(cfg.StateDir)
	if err != nil {
		log.Fatal(err)
	}
	audit := state.NewAudit(cfg.StateDir)

	_ = os.Remove(cfg.Socket)
	apiLn, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		log.Fatal(err)
	}
	// Any local user may connect; the server checks the peer uid.
	if err := os.Chmod(cfg.Socket, 0o666); err != nil {
		log.Fatal(err)
	}
	apiSrv := &http.Server{
		Handler:           (&api.Server{Store: s, State: st, Audit: audit, AllowUID: cfg.AllowUID, ProxyAddr: cfg.ProxyAddr}).Handler(),
		ConnContext:       api.ConnContext,
		ReadHeaderTimeout: 10 * time.Second,
	}

	proxyLn, err := net.Listen("tcp", cfg.ProxyAddr)
	if err != nil {
		log.Fatal(err)
	}
	proxySrv := &http.Server{
		Handler:           &proxy.Proxy{Store: s, State: st, Audit: audit},
		ReadHeaderTimeout: 30 * time.Second,
	}

	errc := make(chan error, 2)
	go func() { errc <- apiSrv.Serve(apiLn) }()
	go func() { errc <- proxySrv.Serve(proxyLn) }()
	log.Printf("secretd: api on %s, proxy on %s, store in %s", cfg.Socket, cfg.ProxyAddr, cfg.StateDir)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Print(err)
		}
	case <-sig:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = apiSrv.Shutdown(ctx)
	_ = proxySrv.Shutdown(ctx)
	_ = os.Remove(cfg.Socket)
}
