package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/blackstonecan/dev-secretd/internal/api"
	"github.com/blackstonecan/dev-secretd/internal/config"
	"github.com/blackstonecan/dev-secretd/internal/dotenv"
	"github.com/blackstonecan/dev-secretd/internal/manifest"
	"github.com/blackstonecan/dev-secretd/internal/runenv"
	"github.com/blackstonecan/dev-secretd/internal/store"
	"golang.org/x/term"
)

func client() (*api.Client, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	return api.NewClient(cfg.Socket), nil
}

// projectFor returns --project, or the project of secrets.yaml in this folder or a parent.
func projectFor(flagValue string) (string, *manifest.Manifest, error) {
	m, err := manifest.Find(".")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", nil, err
	}
	if flagValue != "" {
		return flagValue, m, nil
	}
	if m == nil {
		return "", nil, usageError{"no secrets.yaml here: use --project, or `secret init --project NAME`"}
	}
	return m.Project, m, nil
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	project := fs.String("project", "", "project name")
	user := fs.Bool("user", false, "")
	if err := fs.Parse(args); err != nil {
		return usageError{err.Error()}
	}
	path := manifest.FileName
	switch {
	case *user && *project != "":
		return usageError{"use --project or --user, not both"}
	case *user:
		var err error
		if path, err = manifest.UserPath(); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		*project = store.UserProject
	case *project == store.UserProject:
		return usageError{"\"user\" is the user scope, not a project: use `secret init --user`"}
	case !store.ValidProject(*project):
		return usageError{"--project is required (lowercase letters, digits, . _ -)"}
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	m := &manifest.Manifest{Project: *project, Secrets: map[string]manifest.Entry{}, Path: path}
	if err := m.Save(); err != nil {
		return err
	}
	fmt.Printf("made %s for project %s\n", path, *project)
	return nil
}

func cmdSet(args []string) error {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	project := fs.String("project", "", "")
	user := fs.Bool("user", false, "")
	def := fs.Bool("default", false, "")
	isFile := fs.Bool("file", false, "")
	host := fs.String("host", "", "")
	header := fs.String("header", "", "")
	format := fs.String("format", "", "")
	basic := fs.Bool("basic", false, "")
	basicName := fs.String("basic-user", "", "")
	query := fs.String("query", "", "")
	name, rest := firstArg(args)
	if err := fs.Parse(rest); err != nil {
		return usageError{err.Error()}
	}
	if name == "" || fs.NArg() > 0 {
		return usageError{"usage: secret set NAME [flags]"}
	}
	if *user {
		if *project != "" {
			return usageError{"use --project or --user, not both"}
		}
		*project = store.UserProject
	}
	if *def && *project != store.UserProject {
		return usageError{"--default is for user-scope secrets: add --user"}
	}
	p, m, err := projectFor(*project)
	if err != nil {
		return err
	}

	req := api.SetRequest{Project: p, Name: name, Tier: store.TierRun, Kind: store.KindEnv, Default: *def}
	if *host != "" || *header != "" || *query != "" {
		if *isFile {
			return usageError{"--file is for run-tier secrets only"}
		}
		def := ""
		if *basic && *basicName == "" {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			def = cfg.BasicUser
		}
		user, err := basicUser(*basic, *basicName, def)
		if err != nil {
			return err
		}
		h, extra := store.ParseHosts(*host)
		req.Tier, req.Kind = store.TierProxy, ""
		req.Binding = &store.Binding{Host: h, ExtraHosts: extra, Header: *header, Format: *format, Basic: user, Query: *query}
	} else if *basic || *basicName != "" {
		return usageError{"--basic is for proxy-tier secrets: add --host and --header"}
	} else if *isFile {
		req.Kind = store.KindFile
	}

	value, err := readValue("Value for "+p+"/"+name, *isFile)
	if err != nil {
		return err
	}
	req.Value = value
	c, err := client()
	if err != nil {
		return err
	}
	if err := c.Set(req); err != nil {
		return err
	}
	fmt.Printf("stored %s/%s (tier %s)\n", p, name, req.Tier)
	if p == store.UserProject {
		if *def {
			fmt.Printf("it is a default: every project whose secrets.yaml lists %s gets it, unless the\n"+
				"project has its own %s or its entry says `fallback: none`\n", name, name)
		} else {
			fmt.Printf("projects use it with `fallback: user` in their secrets.yaml entry for %s;\n"+
				"a project secret of the same name always wins\n", name)
		}
		return nil
	}
	if m != nil && m.Project == p {
		if e, ok := m.Secrets[name]; ok {
			if e.Tier != req.Tier {
				fmt.Printf("warning: %s says tier %s for %s; change it to %s\n", m.Path, e.Tier, name, req.Tier)
			}
			return nil
		}
	}
	if req.Tier == store.TierProxy {
		fmt.Printf("add to secrets.yaml:\n  %s:\n    tier: proxy\n    env:\n      SOME_BASE_URL: \"{proxy}\"\n      SOME_API_KEY: placeholder\n", name)
	} else {
		fmt.Printf("add to secrets.yaml:\n  %s:\n    tier: run\n", name)
	}
	return nil
}

// readValue reads a hidden value from the terminal (asked twice), or all of stdin.
func readValue(prompt string, isFile bool) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", err
		}
		v := string(raw)
		if !isFile {
			v = strings.TrimRight(v, "\r\n")
		}
		if v == "" {
			return "", errors.New("empty value on stdin")
		}
		return v, nil
	}
	if isFile {
		return "", usageError{"a file secret is read from stdin: secret set NAME --file < path"}
	}
	fmt.Fprintf(os.Stderr, "%s (hidden): ", prompt)
	a, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Again: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(a) != string(b) {
		return "", errors.New("the two values are not the same")
	}
	if len(a) == 0 {
		return "", errors.New("empty value")
	}
	return string(a), nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	project := fs.String("project", "", "")
	all := fs.Bool("all", false, "")
	if err := fs.Parse(args); err != nil {
		return usageError{err.Error()}
	}
	p := ""
	var m *manifest.Manifest
	if !*all {
		var err error
		if p, m, err = projectFor(*project); err != nil {
			return err
		}
	}
	c, err := client()
	if err != nil {
		return err
	}
	list, err := c.List(p)
	if err != nil {
		return err
	}
	// User-scope secrets this project's manifest falls back to.
	notes := map[string]string{}
	if m != nil && m.Project == p && p != store.UserProject {
		own := map[string]bool{}
		for _, s := range list {
			own[s.Name] = true
		}
		users, err := c.List(store.UserProject)
		if err != nil {
			return err
		}
		for _, s := range users {
			e, listed := m.Secrets[s.Name]
			if !listed || e.Fallback == "none" || (e.Fallback != store.UserProject && !s.Default) {
				continue
			}
			list = append(list, s)
			notes[s.Name] = "fallback"
			if s.Default && e.Fallback == "" {
				notes[s.Name] = "default"
			}
			if own[s.Name] {
				notes[s.Name] = "overridden by " + p
			}
		}
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SECRET\tTIER\tUSE\tLOCKED\tUPDATED\tNOTE")
	for _, s := range list {
		use := string(s.Kind)
		if b := s.Binding; b != nil {
			hosts := strings.Join(b.Hosts(), ",")
			switch {
			case b.Basic != "":
				use = hosts + " header " + b.Header + " basic " + b.Basic
			case b.Header != "":
				use = hosts + " header " + b.Header
			default:
				use = hosts + " query " + b.Query
			}
		}
		note := ""
		if s.Project == store.UserProject {
			if p != store.UserProject && p != "" {
				note = notes[s.Name]
			} else if s.Default {
				note = "default for all projects"
			}
		}
		fmt.Fprintf(w, "%s/%s\t%s\t%s\t%v\t%s\t%s\n", s.Project, s.Name, s.Tier, use, s.Locked, s.UpdatedAt.Format("2006-01-02"), note)
	}
	return w.Flush()
}

func cmdRun(args []string) (int, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	project := fs.String("project", "", "")
	user := fs.Bool("user", false, "")
	if err := fs.Parse(args); err != nil {
		return 0, usageError{err.Error()}
	}
	command := fs.Args()
	if len(command) == 0 {
		return 0, usageError{"usage: secret run [--project P | --user] -- CMD..."}
	}
	var m *manifest.Manifest
	var err error
	if *user {
		if *project != "" {
			return 0, usageError{"use --project or --user, not both"}
		}
		if m, err = manifest.LoadUser(); errors.Is(err, os.ErrNotExist) {
			return 0, usageError{"no user manifest: make it with `secret init --user`"}
		}
	} else if m, err = manifest.Find("."); errors.Is(err, os.ErrNotExist) {
		return 0, usageError{"no secrets.yaml in this folder or its parents"}
	}
	if err != nil {
		return 0, err
	}
	if *project != "" && *project != m.Project {
		return 0, usageError{fmt.Sprintf("--project %s does not match %s (project %s)", *project, m.Path, m.Project)}
	}

	req := api.ResolveRequest{Project: m.Project}
	for _, n := range m.Names() {
		e := m.Secrets[n]
		req.Items = append(req.Items, api.ResolveItem{Name: n, Tier: e.Tier, Fallback: e.Fallback})
	}
	var resolved []api.Resolved
	if len(req.Items) > 0 {
		c, err := client()
		if err != nil {
			return 0, err
		}
		if resolved, err = c.Resolve(req); err != nil {
			return 0, err
		}
	}
	for _, r := range resolved {
		if r.Project != m.Project {
			fmt.Fprintf(os.Stderr, "secret: %s from %s\n", r.Name, r.Project)
		}
	}
	env, err := runenv.Build(m, resolved, os.Getenv("XDG_RUNTIME_DIR"))
	if err != nil {
		return 0, err
	}
	defer env.Cleanup()

	path, err := exec.LookPath(command[0])
	if err != nil {
		return 0, err
	}
	child := exec.Command(path, command[1:]...)
	child.Env = runenv.Merge(os.Environ(), env.Vars)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		return 0, err
	}
	// Forward signals, so Ctrl-C stops the child and the file secrets are removed.
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		for s := range sig {
			_ = child.Process.Signal(s)
		}
	}()
	err = child.Wait()
	signal.Stop(sig)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return exitErr.ExitCode(), nil
	}
	return 0, err
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	project := fs.String("project", "", "")
	keep := fs.String("keep", "", "")
	yes := fs.Bool("yes", false, "")
	file, rest := firstArg(args)
	if err := fs.Parse(rest); err != nil {
		return usageError{err.Error()}
	}
	if file == "" || fs.NArg() > 0 {
		return usageError{"usage: secret import FILE [--project P] [--keep K1,K2] [--yes]"}
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	entries, err := dotenv.Parse(string(raw))
	if err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	p, m, err := projectFor(*project)
	if err != nil {
		return err
	}
	if p == store.UserProject {
		return usageError{"import moves a project's .env; add user-scope secrets with `secret set NAME --user`"}
	}
	if m == nil {
		m = &manifest.Manifest{Project: p, Secrets: map[string]manifest.Entry{}, Path: filepath.Join(filepath.Dir(file), manifest.FileName)}
	} else if m.Project != p {
		return usageError{fmt.Sprintf("--project %s does not match %s (project %s)", p, m.Path, m.Project)}
	}

	kept := map[string]bool{}
	for _, k := range strings.Split(*keep, ",") {
		if k = strings.TrimSpace(k); k != "" {
			kept[k] = true
		}
	}
	var move []dotenv.Entry
	for _, e := range entries {
		if kept[e.Key] || e.Value == "" {
			continue
		}
		if !store.ValidName(e.Key) {
			return fmt.Errorf("%s is not a valid secret name (UPPER_SNAKE_CASE); use --keep for it", e.Key)
		}
		move = append(move, e)
	}
	if len(move) == 0 {
		fmt.Println("nothing to import")
		return nil
	}

	fmt.Printf("These keys move from %s into secretd (project %s, tier run):\n", file, p)
	for _, e := range move {
		fmt.Printf("  %s\n", e.Key)
	}
	if !*yes && !confirm("Continue?") {
		return errors.New("stopped")
	}

	c, err := client()
	if err != nil {
		return err
	}
	var stored []dotenv.Entry
	for _, e := range move {
		err := c.Set(api.SetRequest{Project: p, Name: e.Key, Tier: store.TierRun, Kind: store.KindEnv, Value: e.Value})
		if err != nil {
			// Already stored: keep the line, so no value is lost. Fix it by hand.
			fmt.Fprintf(os.Stderr, "  %s: %v (the line stays in %s)\n", e.Key, err, file)
			continue
		}
		stored = append(stored, e)
		if _, ok := m.Secrets[e.Key]; !ok {
			m.Secrets[e.Key] = manifest.Entry{Tier: store.TierRun}
		}
	}
	if len(stored) == 0 {
		return errors.New("nothing was stored")
	}
	if err := dotenv.RemoveKeys(file, stored, "moved to secretd (secret run)"); err != nil {
		return fmt.Errorf("stored in secretd, but cannot rewrite %s: %w", file, err)
	}
	if err := m.Save(); err != nil {
		return err
	}
	fmt.Printf("moved %d key(s). Start the app with: secret run -- <command>\n", len(stored))
	fmt.Println("If this file was ever committed to git, the old values are in the history: rotate them.")
	return nil
}

func cmdLock(args []string, locked bool) error {
	p := ""
	if len(args) > 0 {
		p = args[0]
	} else {
		var err error
		if p, _, err = projectFor(""); err != nil {
			return err
		}
	}
	c, err := client()
	if err != nil {
		return err
	}
	if err := c.Lock(p, locked); err != nil {
		return err
	}
	fmt.Printf("%s: locked=%v\n", p, locked)
	return nil
}

func cmdStatus() error {
	c, err := client()
	if err != nil {
		return err
	}
	st, err := c.Status()
	if err != nil {
		return err
	}
	fmt.Printf("secretd is running\nproxy:   %s\nsecrets: %d\nlocked:  %s\n", st.ProxyAddr, st.Secrets, strings.Join(st.Locked, ", "))
	return nil
}

// firstArg allows `secret set NAME --flag` (the flag package stops at the first non-flag).
func firstArg(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func confirm(q string) bool {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false
	}
	fmt.Fprintf(os.Stderr, "%s [y/N] ", q)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y")
}
