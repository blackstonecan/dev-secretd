package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/blackstonecan/dev-secretd/internal/api"
	"github.com/blackstonecan/dev-secretd/internal/config"
	"github.com/blackstonecan/dev-secretd/internal/manifest"
	"github.com/blackstonecan/dev-secretd/internal/store"
)

// githubURLRe matches https://github.com/OWNER/REPO[.git][/].
var githubURLRe = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9-]+)/[A-Za-z0-9._-]+?(\.git)?/?$`)

// githubOwner returns the owner of an https GitHub remote URL.
func githubOwner(remoteURL string) (string, error) {
	if strings.HasPrefix(remoteURL, "git@") || strings.HasPrefix(remoteURL, "ssh://") {
		return "", fmt.Errorf("the remote uses SSH (%s); `secret git` needs an https://github.com/ URL "+
			"(git remote set-url origin https://github.com/OWNER/REPO.git)", remoteURL)
	}
	m := githubURLRe.FindStringSubmatch(remoteURL)
	if m == nil {
		return "", fmt.Errorf("the remote is not an https://github.com/OWNER/REPO URL: %s", remoteURL)
	}
	return m[1], nil
}

// gitRule is one url.<base>.insteadOf entry of a git config.
type gitRule struct{ base, insteadOf string }

// gitRules reads the url.*.insteadOf entries of one git config scope.
func gitRules(scope string) ([]gitRule, error) {
	out, err := gitOutput("config", scope, "--get-regexp", `^url\..*\.insteadof$`)
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 { // no matching entries
			return nil, nil
		}
		return nil, err
	}
	var rules []gitRule
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		base := strings.TrimSuffix(strings.TrimPrefix(key, "url."), ".insteadof")
		rules = append(rules, gitRule{base: base, insteadOf: value})
	}
	return rules, nil
}

func gitOutput(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() != 1 {
			return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
		}
	}
	return string(out), err
}

// cmdGit routes a customer's repo through this project's own token: it adds
// an owner-scoped insteadOf rule to the repo's .git/config. Your own repos
// are covered by a global rule and need nothing.
func cmdGit(args []string) error {
	fs := flag.NewFlagSet("git", flag.ContinueOnError)
	off := fs.Bool("off", false, "")
	remote := fs.String("remote", "origin", "")
	name := fs.String("secret", "GITHUB_TOKEN", "")
	noCheck := fs.Bool("no-check", false, "")
	if err := fs.Parse(args); err != nil {
		return usageError{err.Error()}
	}
	if fs.NArg() > 0 {
		return usageError{"usage: secret git [--secret NAME] [--remote NAME] [--no-check] | secret git --off"}
	}
	if _, err := gitOutput("rev-parse", "--git-dir"); err != nil {
		return errors.New("not in a git repository")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	proxyPrefix := "http://" + cfg.ProxyAddr + "/"
	local, err := gitRules("--local")
	if err != nil {
		return err
	}
	if *off {
		return gitOff(local, proxyPrefix)
	}

	// The repo's owner first: your own repos need nothing, not even a project.
	// The raw URL: `git remote get-url` would show it already rewritten.
	rawURL, err := gitOutput("config", "--get", "remote."+*remote+".url")
	if err != nil {
		return fmt.Errorf("no remote %q in this repository", *remote)
	}
	owner, err := githubOwner(strings.TrimSpace(rawURL))
	if err != nil {
		return err
	}
	from := "https://github.com/" + owner + "/"

	// A global rule for this owner means it is your own account.
	global, err := gitRules("--global")
	if err != nil {
		return err
	}
	for _, r := range global {
		if strings.EqualFold(r.insteadOf, from) {
			return fmt.Errorf("%s is covered by your global rule (%s), so it is your own account and needs nothing; "+
				"`secret git` is for a customer's repo", from, r.base)
		}
	}

	m, err := manifest.Find(".")
	if errors.Is(err, os.ErrNotExist) {
		return usageError{"no secrets.yaml here: run `secret init --project NAME` first"}
	}
	if err != nil {
		return err
	}
	if m.Project == store.UserProject {
		return usageError{"`secret git` is for a project; your own repos use the global rule"}
	}

	if err := checkGitToken(m.Project, *name); err != nil {
		return err
	}

	base := proxyPrefix + m.Project + "/" + *name + "/github.com/" + owner + "/"
	// Replace earlier secretd rules for this owner (another secret name).
	for _, r := range local {
		if strings.EqualFold(r.insteadOf, from) && strings.HasPrefix(r.base, proxyPrefix) && r.base != base {
			if _, err := gitOutput("config", "--local", "--remove-section", "url."+r.base); err != nil {
				return err
			}
			fmt.Printf("removed rule %s\n", r.base)
		}
	}
	if _, err := gitOutput("config", "--local", "url."+base+".insteadOf", from); err != nil {
		return err
	}
	fmt.Printf("this repo now reaches %s through %s/%s (only in this repo's .git/config)\n", from, m.Project, *name)
	if *noCheck {
		return nil
	}
	return checkGitAccess(*remote, m.Project, *name)
}

// checkGitToken makes sure the project has its own secret NAME, bound to
// github.com with Basic auth, so git can use it through the proxy.
func checkGitToken(project, name string) error {
	c, err := client()
	if err != nil {
		return err
	}
	list, err := c.List(project)
	if err != nil {
		return err
	}
	setCmd := fmt.Sprintf("secret set %s --host api.github.com,github.com --header Authorization --basic", name)
	i := slices.IndexFunc(list, func(s api.Info) bool { return s.Name == name })
	if i < 0 {
		return fmt.Errorf("project %s has no %s of its own; add the customer's token first (typed hidden):\n  %s", project, name, setCmd)
	}
	b := list[i].Binding
	if list[i].Tier != store.TierProxy || b == nil || !slices.ContainsFunc(b.Hosts(), func(h string) bool { return strings.EqualFold(h, "github.com") }) || !b.UsesBasic() {
		return fmt.Errorf("%s/%s is not bound to github.com with Basic auth; fix it in your own terminal:\n"+
			"  /usr/bin/sudo secret bind %s/%s --host api.github.com,github.com --header Authorization --basic", project, name, project, name)
	}
	return nil
}

// checkGitAccess runs a read-only `git ls-remote` through the new rule.
func checkGitAccess(remote, project, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "ls-remote", "--heads", remote)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if i := strings.LastIndex(msg, "\n"); i >= 0 {
			msg = msg[i+1:]
		}
		return fmt.Errorf("the rule is in place, but GitHub refused %s/%s: %s\n"+
			"  check that the token can reach this repo (a fine-grained token reaches only repos of its owner),\n"+
			"  that its owner can push here, and that secretd is running; undo with `secret git --off`", project, name, msg)
	}
	fmt.Println("checked: GitHub accepts the token for this repo (git ls-remote)")
	return nil
}

// gitOff removes this repo's rules that point at secretd.
func gitOff(local []gitRule, proxyPrefix string) error {
	n := 0
	for _, r := range local {
		if !strings.HasPrefix(r.base, proxyPrefix) {
			continue
		}
		if _, err := gitOutput("config", "--local", "--remove-section", "url."+r.base); err != nil {
			return err
		}
		fmt.Printf("removed rule %s -> %s\n", r.insteadOf, r.base)
		n++
	}
	if n == 0 {
		fmt.Println("this repo has no secretd rule")
	}
	return nil
}
