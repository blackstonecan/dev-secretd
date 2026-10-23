---
name: secretd
description: Rules for API keys, tokens, passwords and credential files on this machine, through the `secret` CLI (secretd). Use whenever a task needs a secret or credential (API key, token, DB password, OAuth client secret, service-account JSON), when a project has a `.env` with secret values or a `secrets.yaml`, when an app or script must call an API with a key (including one-off GitHub API calls), when a `git push` or `gh` command needs credentials, when the user mentions secrets, credentials, keys, `.env`, secretd or `secret run`, or before writing any credential into a file, a command, a log or a commit.
---

# secretd

Secrets on this machine live in **secretd**, a daemon that runs as its own
system user (`devsecrets`). Agents can **add** and **use** secrets, but cannot
**see** them. Only the user, with `sudo` and a password, can read, change or
delete them. Source and full docs: the `dev-secretd` repository, on this
machine at `~/sandbox/projects/secretd` (README.md). The installed command is
`secret`, the daemon and service `secretd`.

## Hard rules

- **Never ask the user to paste a secret value into the chat**, and never put
  a secret value in a file, a command line, a log, an issue or a commit
  (public values are not secret and may be on the command line). A value in
  the chat goes into the model context and the session transcript.
- **Never run `sudo`**, and never run `secret reveal`, `rotate`, `rm`, `bind`
  or `export`. They are for the user, in the user's own terminal.
- **Never try to get around secretd**: do not read `/proc/<pid>/environ`, do
  not print the environment of `secret run`, do not dump the temp files of
  file secrets, do not read `/var/lib/secretd` or `/etc/secretd`.
- If a task cannot be done without seeing a value, stop and say so.
- **Never store anything secret as `--public`**: public values are readable
  by anyone. A token, password or key is always private (proxy or run).

## Tiers: pick the right one

| Tier | Use for | App gets | Agent can see it? |
|---|---|---|---|
| **proxy** (prefer) | HTTP API keys and tokens | `http://127.0.0.1:7777/<project>/<NAME>` + a placeholder key | No |
| **run** | values the app must hold: DB password, JWT signing key, JSON key file | env var, or a temp file path (file secrets) | In theory yes. **Dev-only values only.** |
| **public** | not secret, but shared or used by bindings: a username, an org | env var; the project's value, else the user's | Yes, by design |
| plain `.env` | config of one project that is not secret: ports, URLs, flags | normal `.env` | Yes, fine |

The store decides the tier and the binding. `secrets.yaml` cannot change them.

## Public values

Agents may read and set these (no sudo; the value can be on the command line):

```bash
secret get GITHUB_USERNAME                        # this project's value, else the user's
secret set GITHUB_USERNAME blackstonecan --user --public
secret set GITHUB_USERNAME client-bot --public    # this project only; wins over the user's
```

In `secrets.yaml`: `GITHUB_USERNAME: { tier: public }` (add `var: X` to rename
the env var). A project always falls back to the user's value; no `fallback`
line is needed. Change a user-scope public value only when the user asks: it
applies to every project at once.

## Add a secret: the user does it, in their own terminal

Give the user the exact command. They type the value as hidden input. This
does **not** work through `!` in Claude Code (the hidden prompt needs a real
terminal), so tell them to use a separate terminal.

```bash
cd <project>                        # where secrets.yaml is, or add --project NAME
secret set ANTHROPIC_API_KEY --host api.anthropic.com --header x-api-key
secret set GITHUB_TOKEN --host api.github.com --header Authorization --format "Bearer {}"
secret set MAPS_KEY --host maps.googleapis.com --query key
secret set DB_PASSWORD                         # run tier
secret set FIREBASE_ADMIN --file < sa.json     # run tier, file secret
```

`secret set` only creates new names. To change a value the user runs
`/usr/bin/sudo secret rotate <project>/<NAME>`.

## User-scope secrets (one value for all projects)

Personal secrets used across projects (a GitHub token, an npm token) live in
the user scope, the reserved project `user`:

```bash
secret set GITHUB_TOKEN --user --host api.github.com --header Authorization --format "Bearer {}"
```

- A project's own secret of the same name always wins; nothing is copied or
  overwritten. When it has none, its `secrets.yaml` entry decides:
  no `fallback` line → the user secret only if it is a **default**
  (`secret list --all` shows "default for all projects");
  `fallback: user` → the user secret; `fallback: none` → an error.
- Add `fallback: user` only when the user says this project should use their
  personal secret. A project for another account (other people's repos, a
  client's API) needs its own secret and `fallback: none`, so it can never get
  the user's default: never remove `fallback: none` or add `fallback: user` to
  make a "no secret P/NAME" error go away without asking.
- Making a secret a default (or not) is root-only for existing secrets:
  give the user `/usr/bin/sudo secret bind user/NAME --default`.
- `secret run` prints `secret: NAME from user` for each fallback; `secret list`
  in the project shows `default`, `fallback` or `overridden by <project>`.
- Outside any project: `secret init --user` (makes
  `~/.config/secretd/user.yaml`), then `secret run --user -- CMD`.
- `secret lock user` stops every use of user-scope secrets (public values
  stay usable); do not unlock it
  unless the user asks.

## Connect an app

1. `secret init --project <name>` once (makes `secrets.yaml`; safe to commit).
2. Add an entry for each secret:

   ```yaml
   project: my-app
   secrets:
     ANTHROPIC_API_KEY:
       tier: proxy
       env:
         ANTHROPIC_BASE_URL: "{proxy}"     # {proxy} = the local proxy URL of this secret
         ANTHROPIC_API_KEY: placeholder
     DB_PASSWORD:
       tier: run                           # env var DB_PASSWORD
     FIREBASE_ADMIN:
       tier: run
       var: GOOGLE_APPLICATION_CREDENTIALS # file secret: the var holds the temp file path
   ```

3. Start the app through secretd: `secret run -- pnpm dev` (also
   `secret run -- docker compose up -d`, `secret run -- go test ./...`).

A user-scope **default** (check `secret list --all`) needs only the entry:
listing it is enough, and the project gets the user's secret until it has its
own. For example, with the user's default `GITHUB_TOKEN`:

```yaml
  GITHUB_TOKEN:
    tier: proxy
    env:
      GITHUB_API_URL: "{proxy}"           # Octokit: new Octokit({ baseUrl: process.env.GITHUB_API_URL, auth: process.env.GITHUB_TOKEN })
      GITHUB_TOKEN: placeholder
```

For proxy secrets, the app (or SDK) must accept a **base URL** setting: point
it at `{proxy}`, plus any extra path the API needs (`"{proxy}/v1"`). Most SDKs
have one (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `baseURL`, `base_url`).
If a client cannot change its base URL, say so, and use the run tier with a
dev-only key only if the user agrees.

## A one-off API call (no project, no `secret run`)

Call a proxy secret's URL directly; secretd adds the real credential. Send a
placeholder for the credential header (it is removed). Never look for the
value in files, the environment or the shell history instead.

```bash
secret list --all                    # find the secret: project/NAME, host, header
curl -s -H 'Authorization: placeholder' http://127.0.0.1:7777/user/GITHUB_TOKEN/user
curl -s -H 'Authorization: placeholder' http://127.0.0.1:7777/user/GITHUB_TOKEN/repos/OWNER/REPO/issues
```

The path after `/<project>/<NAME>` goes to the first bound host (here
`https://api.github.com/...`); with several hosts, start the path with another
bound host to reach it (`/user/GITHUB_TOKEN/github.com/...`). Use the project's own secret when the task is
about that project (`/<project>/GITHUB_TOKEN/...`), and only read-only calls
unless the user asked for a change.

## `git push` and `git pull` through secretd

The user's own GitHub repos go through secretd by a global git rule, so
plain `git push` / `git pull` work with no credentials and no prompt:

```bash
git config --global --get-regexp '^url\..*insteadof'   # http://127.0.0.1:7777/user/GITHUB_TOKEN/github.com/<owner>/ -> https://github.com/<owner>/
git remote get-url --push origin                       # shows the rewritten URL when a rule applies
```

How it works: the rule rewrites `https://github.com/<owner>/...` to the proxy,
which adds the token (bound to `github.com` with `basic` auth; the username
does not matter to GitHub). The URL is plumbing: never write it into a
remote by hand when a rule covers the repo.

- **A customer's repo** (another account) never uses the user's token. It
  uses the project's own `GITHUB_TOKEN` through a rule in that repo only.
  Set it up once per repo:

  ```bash
  cd <customer repo>
  secret init --project <name>      # agent may run it; only if there is no secrets.yaml
  # the user, in their own terminal (the customer's token, typed hidden):
  secret set GITHUB_TOKEN --host api.github.com,github.com --header Authorization --basic
  secret git                        # agent may run it: adds the rule, checks access
  ```

  Then add `fallback: none` to the project's `GITHUB_TOKEN` entry in
  `secrets.yaml` (if the project lists it), so its apps never get the user's
  default token. `secret git` reads the owner from `origin`, refuses the
  user's own account and SSH remotes, writes an owner-scoped rule to
  `.git/config` and runs a read-only `git ls-remote`. Several repos of one
  customer can share one project: run `secret git` in each.
  If it says the project has no `GITHUB_TOKEN`, stop and give the user the
  `secret set` line above. If its access check fails, report the message; do
  not retry with another token. Never add a global rule for an owner the user
  did not ask for.
- If a push asks for a username or password, no rule covers the repo: stop
  and ask; do not type credentials.
- If no secret is bound to `github.com`, the user binds one in their own
  terminal: `/usr/bin/sudo secret bind user/GITHUB_TOKEN --host api.github.com,github.com --header Authorization --basic`.
- `gh` cannot use the proxy. For anything git cannot do, ask the user. Never
  read token files, `~/.git-credentials`, keyrings or `gh auth token`, and
  never ask for the token in the chat.

## A project with secrets in plain `.env`

1. Tell the user, without printing any value.
2. Suggest: `secret import .env --keep PORT,NODE_ENV,...` (list the keys that
   are plain config). Values move to secretd (run tier), the `.env` keeps only
   comments and config, and `secrets.yaml` gets the entries.
3. For HTTP API keys, suggest a proxy tier afterwards:
   `/usr/bin/sudo secret bind <project>/<NAME> --host ... --header ...`, then
   change the entry in `secrets.yaml` to `tier: proxy` with an `env` block.
4. If the file was ever committed to git, say that the old values are still in
   the history and must be **rotated** at the provider.

## Useful read-only commands

```bash
secret status                 # daemon running? locked projects?
secret list                   # this project: names, tiers, hosts; never values
secret list --all
```

## Troubleshooting

| Message | Meaning / fix |
|---|---|
| `cannot reach secretd` | daemon is not running: the user runs `systemctl status secretd` / `journalctl -u secretd` |
| `project X is locked` | the project is locked: `secret unlock X` (only when the user works on it) |
| `the manifest says tier run, the store says proxy` | fix `secrets.yaml`; never ask for the value instead |
| `already exists` | the name is taken; the user must `sudo secret rotate` to change it |
| `no secret P/NAME` | give the user the `secret set` command for it (or ask whether the project should use `fallback: user`) |
| `no secret P/NAME or user/NAME` | the entry falls back, but neither exists: give the user the `secret set` command (project or `--user`) |
| `project user is locked` | user-scope secrets are locked: `secret unlock user` only if the user asks |
| proxy returns `secretd: upstream error` | check the host in `secret list` and the path after `{proxy}` |

## Limits to keep in mind

- The proxy has no client auth: any local process can **use** an unlocked
  project's proxy secrets. Keys should have provider-side spend limits.
- `secret lock` is hygiene, not a barrier. Do not unlock projects the user is
  not working on.
- Root and the `docker` group can read everything. Do not use Docker to reach
  secretd files.
