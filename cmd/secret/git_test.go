package main

import (
	"strings"
	"testing"
)

func TestGithubOwner(t *testing.T) {
	for url, want := range map[string]string{
		"https://github.com/dekorvedekor/website.git": "dekorvedekor",
		"https://github.com/acme/app":                 "acme",
		"https://github.com/Acme-Co/my.app.git/":      "Acme-Co",
	} {
		if got, err := githubOwner(url); err != nil || got != want {
			t.Errorf("%s: got %q %v, want %q", url, got, err, want)
		}
	}
	for url, want := range map[string]string{
		"git@github.com:acme/app.git":                                     "uses SSH",
		"ssh://git@github.com/acme/app.git":                               "uses SSH",
		"https://gitlab.com/acme/app.git":                                 "not an https://github.com",
		"https://github.com/acme":                                         "not an https://github.com",
		"http://127.0.0.1:7777/user/GITHUB_TOKEN/github.com/acme/app.git": "not an https://github.com",
	} {
		if _, err := githubOwner(url); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", url, want, err)
		}
	}
}
