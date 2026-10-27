// Command linode-ddns serves a dyndns-style HTTP API that updates Linode DNS
// records.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"linode-ddns/internal/config"
	"linode-ddns/internal/linode"
	"linode-ddns/internal/server"
)

const usage = `Usage:
  linode-ddns [serve] --config=PATH [--listen=ADDR]
  linode-ddns hash-password    (reads the password from stdin)
`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}

	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "hash-password":
		err = hashPassword(os.Stdin, os.Stdout, os.Stderr)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "linode-ddns:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage); fs.PrintDefaults() }
	configPath := fs.String("config", "", "path to the YAML config file (required)")
	listen := fs.String("listen", "", "listen address, overrides the config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		fs.Usage()
		return errors.New("--config is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if cfg.TLS == nil && !loopback(cfg.Listen) {
		log.Warn("serving plain HTTP on a non-loopback address; credentials travel in cleartext unless a TLS-terminating proxy is in front",
			"addr", cfg.Listen)
	}
	if fi, err := os.Stat(*configPath); err == nil && fi.Mode().Perm()&0o077 != 0 {
		log.Warn("config file holds Linode API tokens but is accessible by group or others; restrict it with chmod 600",
			"path", *configPath, "mode", fi.Mode().Perm())
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.New(cfg, linode.NewResolver(linode.NewClient()), log),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Listen, "tls", cfg.TLS != nil, "users", len(cfg.Users))
		if cfg.TLS != nil {
			errc <- srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// loopback reports whether the listen address binds only to a loopback
// interface.
func loopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// hashPassword reads a password from the first line of in and writes its
// bcrypt hash to out.
func hashPassword(in io.Reader, out, prompt io.Writer) error {
	fmt.Fprint(prompt, "Password: ")
	pw, err := readPassword(in)
	if err != nil {
		return err
	}
	fmt.Fprintln(prompt)
	if pw == "" {
		return errors.New("empty password")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, string(hash))
	return nil
}

// readPassword reads one line from in. When in is a terminal, the input is not
// echoed.
func readPassword(in io.Reader) (string, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		b, err := term.ReadPassword(int(f.Fd()))
		return string(b), err
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
