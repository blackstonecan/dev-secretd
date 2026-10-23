package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/blackstonecan/dev-secretd/internal/config"
	"github.com/blackstonecan/dev-secretd/internal/state"
	"github.com/blackstonecan/dev-secretd/internal/store"
)

// rootCommand runs commands that need the master key. Only root can decrypt
// it, so these commands work only through sudo.
func rootCommand(cmd string, args []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("`secret %s` needs root: run /usr/bin/sudo secret %s ... in your own terminal", cmd, cmd)
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	key, err := config.RootKey(cfg.MasterCred)
	if err != nil {
		return err
	}
	s, err := store.Open(cfg.StateDir, key)
	if err != nil {
		return err
	}
	audit := state.NewAudit(cfg.StateDir)
	who := "sudo user=" + os.Getenv("SUDO_USER")

	switch cmd {
	case "reveal":
		return rootReveal(s, audit, who, args)
	case "rotate":
		return rootRotate(s, audit, who, args)
	case "rm":
		return rootRm(s, audit, who, args)
	case "bind":
		return rootBind(s, audit, who, args, cfg.BasicUser)
	case "export":
		return rootExport(s, audit, who, args)
	}
	return fmt.Errorf("unknown command %q", cmd)
}

func oneKey(args []string) (string, string, error) {
	if len(args) != 1 {
		return "", "", usageError{"want one PROJECT/NAME"}
	}
	return splitKey(args[0])
}

func rootReveal(s *store.Store, audit *state.Audit, who string, args []string) error {
	p, n, err := oneKey(args)
	if err != nil {
		return err
	}
	sec, err := s.Get(p, n)
	audit.Log(state.Event{Op: "reveal", Project: p, Name: n, Caller: who, Error: errString(err)})
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Shown in this terminal only. Do not run reveal inside an agent session.")
	fmt.Println(sec.Value)
	return nil
}

func rootRotate(s *store.Store, audit *state.Audit, who string, args []string) error {
	p, n, err := oneKey(args)
	if err != nil {
		return err
	}
	sec, err := s.Get(p, n)
	if err != nil {
		return err
	}
	value, err := readValue("New value for "+p+"/"+n, sec.Kind == store.KindFile)
	if err != nil {
		return err
	}
	err = s.Rotate(p, n, value, time.Now())
	audit.Log(state.Event{Op: "rotate", Project: p, Name: n, Caller: who, Error: errString(err)})
	if err != nil {
		return err
	}
	fmt.Printf("rotated %s/%s\n", p, n)
	return nil
}

func rootRm(s *store.Store, audit *state.Audit, who string, args []string) error {
	p, n, err := oneKey(args)
	if err != nil {
		return err
	}
	err = s.Delete(p, n)
	audit.Log(state.Event{Op: "rm", Project: p, Name: n, Caller: who, Error: errString(err)})
	if err != nil {
		return err
	}
	fmt.Printf("deleted %s/%s\n", p, n)
	return nil
}

func rootBind(s *store.Store, audit *state.Audit, who string, args []string, defaultBasic string) error {
	key, rest := firstArg(args)
	fs := flag.NewFlagSet("bind", flag.ContinueOnError)
	host := fs.String("host", "", "")
	header := fs.String("header", "", "")
	format := fs.String("format", "", "")
	basic := fs.Bool("basic", false, "")
	basicName := fs.String("basic-user", "", "")
	query := fs.String("query", "", "")
	run := fs.Bool("run", false, "")
	isFile := fs.Bool("file", false, "")
	def := fs.Bool("default", false, "")
	noDef := fs.Bool("no-default", false, "")
	if err := fs.Parse(rest); err != nil {
		return usageError{err.Error()}
	}
	p, n, err := splitKey(key)
	if err != nil {
		return err
	}
	if *def || *noDef {
		if *def && *noDef || *run || *isFile || *host != "" || *header != "" || *format != "" || *query != "" || *basic || *basicName != "" {
			return usageError{"use --default or --no-default alone"}
		}
		err = s.SetDefault(p, n, *def, time.Now())
		audit.Log(state.Event{Op: "bind", Project: p, Name: n, Caller: who, Detail: "default=" + strconv.FormatBool(*def), Error: errString(err)})
		if err != nil {
			return err
		}
		if *def {
			fmt.Printf("%s/%s is now a default: projects that list %s get it unless they have their own or say `fallback: none`\n", p, n, n)
		} else {
			fmt.Printf("%s/%s is no longer a default: projects need `fallback: user` to use it\n", p, n)
		}
		return nil
	}
	tier, kind := store.TierProxy, store.Kind("")
	var b *store.Binding
	if *run {
		tier, kind = store.TierRun, store.KindEnv
		if *isFile {
			kind = store.KindFile
		}
	} else {
		user, err := basicUser(*basic, *basicName, defaultBasic)
		if err != nil {
			return err
		}
		h, extra := store.ParseHosts(*host)
		b = &store.Binding{Host: h, ExtraHosts: extra, Header: *header, Format: *format, Basic: user, Query: *query}
	}
	err = s.Rebind(p, n, tier, kind, b, time.Now())
	detail := string(tier)
	if b != nil {
		detail += " " + strings.Join(b.Hosts(), ",")
		if b.Basic != "" {
			detail += " basic " + b.Basic
		}
	}
	audit.Log(state.Event{Op: "bind", Project: p, Name: n, Caller: who, Detail: detail, Error: errString(err)})
	if err != nil {
		return err
	}
	fmt.Printf("%s/%s is now tier %s\n", p, n, tier)
	return nil
}

// rootExport writes all secrets, encrypted with age to the given public key.
// Decrypt with: age -d -i KEY_FILE FILE
func rootExport(s *store.Store, audit *state.Audit, who string, args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	recipient := fs.String("recipient", "", "")
	out := fs.String("out", "", "")
	if err := fs.Parse(args); err != nil {
		return usageError{err.Error()}
	}
	if *recipient == "" || *out == "" {
		return usageError{"usage: secret export --recipient AGE_PUBLIC_KEY --out FILE"}
	}
	list, err := s.List("")
	if err != nil {
		return err
	}
	plain, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	var errb bytes.Buffer
	cmd := exec.Command("age", "-r", *recipient, "-o", *out)
	cmd.Stdin, cmd.Stderr = bytes.NewReader(plain), &errb
	err = cmd.Run()
	audit.Log(state.Event{Op: "export", Caller: who, Detail: strconv.Itoa(len(list)) + " secrets", Error: errString(err)})
	if err != nil {
		return fmt.Errorf("age: %v: %s", err, bytes.TrimSpace(errb.Bytes()))
	}
	// Give the backup to the sudo user, not to root.
	if uid, err := strconv.Atoi(os.Getenv("SUDO_UID")); err == nil {
		gid, _ := strconv.Atoi(os.Getenv("SUDO_GID"))
		_ = os.Chown(*out, uid, gid)
	}
	if err := os.Chmod(*out, 0o600); err != nil {
		return err
	}
	fmt.Printf("exported %d secret(s) to %s (age-encrypted)\n", len(list), *out)
	return nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, store.ErrNotFound) {
		return "not found"
	}
	return err.Error()
}
