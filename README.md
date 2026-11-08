# dev-secretd

Store secrets that agents can **use** but cannot **see**: a secret broker for
a development machine where AI coding agents run, not a production secret
manager. One store for all projects on this machine. Your user (and every agent that runs as your user)
can add secrets and use them; only root (you, with `sudo` and your password)
can read, change or delete them.

The installed pieces keep the short names: the `secret` CLI, the `secretd`
daemon and systemd service, and `/etc/secretd`, `/var/lib/secretd`.

## How it works

```
your user (you, Claude Code, other agents)
   │  secret set / list / run / import / lock      ← Unix socket, peer uid checked
   │  http://127.0.0.1:7777/<project>/<NAME>/...    ← proxy, placeholder credential
   ▼
secretd  (system user devsecrets, systemd service)
   ├─ /var/lib/secretd/store.enc   AES-256-GCM, mode 0600, owner devsecrets
   ├─ master key                   systemd-creds (host key + TPM), only for the service
   ├─ proxy                        adds the secret, HTTPS to the bound host only, masks it in responses
   └─ audit.log                    every use, never a value

root (sudo secret reveal / rotate / rm / bind / export) reads the store directly.
```

### Tiers

| Tier | For | The app gets | Can an agent see the value? |
|---|---|---|---|
| **proxy** | HTTP API keys | a local base URL + a placeholder key | **No** |
| **run** | values the app must hold (DB password, JWT key, a JSON key file) | env var, or a temp file in `$XDG_RUNTIME_DIR` (RAM), removed at exit | In theory yes (same user). **Use dev-only values.** |
| **public** | values that are not secret but shared, often with secrets (a username, an org) | env var; project value, else the user's | Yes, by design (`secret get`) |
| plain `.env` | config of one project that is not secret (ports, URLs) | the normal `.env` | Yes, and that is fine |

The **store** decides the tier and the binding of each secret. A changed
`secrets.yaml` cannot turn a proxy secret into a run secret or send it to
another host: `secret run` refuses when the manifest and the store differ.
Only `sudo secret bind` changes a tier or a binding.

## Install

```bash
bash scripts/build.sh              # as your user: vet, test, build dist/
sudo bash install/setup.sh         # as you, in your own terminal
secret status
```

Check that sudo asks for the password every time:

```bash
sudo -k; sudo true                 # sudo now remembers your password
/usr/bin/sudo secret reveal x/Y    # must ask for the password again
```

Claude Code skill (teaches agents these rules; run as your user):

```bash
ln -sfn "$PWD/skill/secretd" ~/.claude/skills/secretd
```

Remove: `sudo bash install/setup.sh --uninstall` (keeps the key and the store)
or `--purge` (deletes everything).

## Use

```bash
cd my-project
secret init --project my-project

# proxy tier: the value never leaves secretd
secret set ANTHROPIC_API_KEY --host api.anthropic.com --header x-api-key
secret set MAPS_KEY --host maps.googleapis.com --query key
secret set GITHUB_TOKEN --host api.github.com --header Authorization --format "Bearer {}"

# run tier (dev-only values)
secret set DB_PASSWORD
secret set FIREBASE_ADMIN --file < service-account.json

# move an existing .env (PORT stays as plain config)
secret import .env --keep PORT

secret list
secret run -- pnpm dev
```

`secrets.yaml` (commit it; it holds no values):

```yaml
project: my-project
secrets:
  ANTHROPIC_API_KEY:
    tier: proxy
    env:
      ANTHROPIC_BASE_URL: "{proxy}"
      ANTHROPIC_API_KEY: placeholder
  DB_PASSWORD:
    tier: run
  FIREBASE_ADMIN:
    tier: run
    var: GOOGLE_APPLICATION_CREDENTIALS   # file secret: the var holds the temp file path
```

`secret set` only adds new names. To change a value: `sudo secret rotate P/NAME`.

### User-scope secrets

For a secret you use across projects, like a personal GitHub token, store it
once in the user scope (the reserved project `user`):

```bash
secret set GITHUB_TOKEN --user --host api.github.com --header Authorization --format "Bearer {}"
```

A project uses it only when its entry says so (opt-in), and its own secret of
the same name always wins:

```yaml
secrets:
  GITHUB_TOKEN:
    tier: proxy
    fallback: user        # use user/GITHUB_TOKEN unless this project has its own
    env:
      GITHUB_API_URL: "{proxy}"
      GITHUB_TOKEN: placeholder
```

- Without `fallback: user`, a missing project secret is an error, so a project
  that should use its own token (another account's repos) never silently gets
  yours. Give it its own: `secret set GITHUB_TOKEN` in that project.

**Defaults.** For a secret most projects use, make it a default: then every
project that lists the name gets it with no `fallback` line, unless it has
its own secret of that name.

```bash
secret set GITHUB_TOKEN --user --default --host api.github.com --header Authorization --format "Bearer {}"
/usr/bin/sudo secret bind user/GITHUB_TOKEN --default      # an existing secret
/usr/bin/sudo secret bind user/GITHUB_TOKEN --no-default   # back to opt-in
```

A project that must never get it (a client's repos) says `fallback: none`:
then a missing project secret is an error again.

| Entry says | Project has its own | Project has none |
|---|---|---|
| nothing | its own | the user secret if it is a default, else an error |
| `fallback: user` | its own | the user secret |
| `fallback: none` | its own | an error |

Turning a default on or off for an existing secret is root-only, like
`bind`; `secret set --user --default` can only make a new one.

- Nothing is copied or overwritten: the fallback is a lookup at `secret run`
  time. The user value changes only with `sudo secret rotate user/NAME`.
- Only a *missing* project secret falls back. A project secret with the wrong
  tier is an error. The store decides the tier and host of whichever secret is
  used.
- `secret run` prints `secret: NAME from user` on stderr for each fallback, and
  the audit log records `"detail":"run from user"` (or `proxy from user`).
  `secret list` in a project marks the user secrets it falls back to
  (`fallback`, or `overridden by <project>`).
- `secret lock user` blocks every use of user-scope secrets, in every project
  and on the proxy; projects' own secrets keep working. Public values are not
  secret and stay usable.
- Outside projects: `secret init --user` makes `~/.config/secretd/user.yaml`
  (`project: user`); list secrets there and use `secret run --user -- CMD`.

### Public values

Some values belong with secrets but are not secret: a username, an org, an
account ID. Store them as **public** values, in a project or the user scope:

```bash
secret set GITHUB_USERNAME blackstonecan --user --public   # the value may be on the command line
secret get GITHUB_USERNAME                                 # this project's value, else the user's
secret list --all                                          # shows public values: "= blackstonecan"
```

- Anyone can read them (`get`, `list`), and you can change them without sudo:
  run the same `set` again. Changes are in the audit log.
- A project uses its own value, else the user's: always, with no `fallback`
  line and regardless of `secret lock user`. `fallback: none` opts out.
- An app gets one as an env var through `secret run`: list it in
  `secrets.yaml` as `GITHUB_USERNAME: { tier: public }` (`var:` renames it).
- A name is either private or public. A public value never replaces a private
  secret, `get` never prints a private one, a manifest that says `tier: public`
  for a private secret gets a tier error (never the value), and `bind` never
  converts between the two.
- Public values never go through the proxy. A binding can read one by name
  (`--basic-user NAME`, below), for services that need a real username.

### Several hosts, and git over HTTPS

One secret can go to several hosts (up to 8, HTTPS only), so one GitHub token
serves the API and git:

```bash
/usr/bin/sudo secret bind user/GITHUB_TOKEN --host api.github.com,github.com --header Authorization --basic
```

- The first host is the default: `/user/GITHUB_TOKEN/<path>` goes to
  `https://api.github.com/<path>`. A first path segment that is exactly one of
  the bound hosts picks that host: `/user/GITHUB_TOKEN/github.com/<path>` goes
  to `https://github.com/<path>`. A host that is not bound is never reached.
  In a manifest: `"{proxy}/github.com"`.
- `--basic` sends `Authorization: Basic base64(x-access-token:token)`, which
  git over HTTPS needs (GitHub's API accepts it too). GitHub takes the account
  from the token and ignores the username, so a GitHub token needs nothing
  else.
- `--basic-user NAME` takes the username from the public value NAME instead,
  for services that check it (the secret's project first, then the user
  scope, read at each request; a missing value fails the request before
  anything is sent).
- The proxy masks the base64 form in responses as well as the raw value.

#### Your own repos: one git rule

Route every repo of your account through secretd. Remote URLs stay as they
are, and nothing is stored per repo:

```bash
git config --global url."http://127.0.0.1:7777/user/GITHUB_TOKEN/github.com/OWNER/".insteadOf "https://github.com/OWNER/"
```

Then `git push`, `git pull` and `git clone https://github.com/OWNER/...` go
through secretd (pushes and private fetches alike). Repos of other owners do
not match the rule and are never sent your token.

#### Customer repos: `secret git`

A repo of another account (a customer's) uses that account's token, stored
as the project's own secret, through a rule in that repo only:

```bash
cd ~/path/to/customer-repo
secret init --project customer-app          # once, if the project has no secrets.yaml
secret set GITHUB_TOKEN --host api.github.com,github.com --header Authorization --basic   # their token, typed hidden
secret git                                  # add the rule, then check access
```

`secret git` reads the owner from `origin` (an `https://github.com/OWNER/REPO`
URL), checks that the project has its own `GITHUB_TOKEN` bound to
`github.com` with Basic auth, and adds to that repo's `.git/config`:

```
[url "http://127.0.0.1:7777/customer-app/GITHUB_TOKEN/github.com/OWNER/"]
    insteadOf = https://github.com/OWNER/
```

Then it checks access with a read-only `git ls-remote`.

- The rule covers only that owner, in that repo: another GitHub remote there
  and your own repos are unaffected. It refuses an owner your global rule
  already covers (your own account) and SSH remotes.
- It is ordinary git config: it applies to you and to agents alike. While
  secretd is stopped, pushes and pulls in that repo fail instead of asking
  for a password.
- `secret git --off` removes the repo's secretd rules. `--secret NAME` uses
  another project secret, `--remote R` another remote, `--no-check` skips the
  access check.
- Add `fallback: none` to the project's `GITHUB_TOKEN` entry in
  `secrets.yaml`, so its apps never get your default token either.
- If the check fails: the token must be able to reach the repo (a
  fine-grained token reaches only repos of its owner) and its account must be
  allowed to push there.
- Pushing to another person's repo with your own account (as a collaborator)
  is not covered: a fine-grained token cannot reach another user's personal
  repos, so it would need a separate classic token.

### OAuth2 APIs: a refresh token that never leaves secretd

Google and other OAuth2 APIs want a short-lived access token, made from a
refresh token with the client id and the client secret. A refresh token
opens the whole account, so it is a proxy secret with an **OAuth binding**:
secretd calls the token endpoint itself, caches the access token until
shortly before it expires, and adds `Authorization: Bearer <access>` to each
request. On a 401 from the API it refreshes once and sends the request once
more. The app sees neither the refresh token, the client secret nor the
access token (the access token is masked in responses like other values).

Three parts, all by name:

```bash
# the client id is not secret: a public value
secret set GMAIL_OAUTH_CLIENT_ID 1234-abc.apps.googleusercontent.com --public
# the client secret: a proxy secret bound to the token endpoint's host, so it
# never leaves secretd either (Basic auth is how a token endpoint takes it)
secret set GMAIL_OAUTH_CLIENT_SECRET --host oauth2.googleapis.com --header Authorization --basic-user GMAIL_OAUTH_CLIENT_ID
# the refresh token: bound to the API hosts, with the token endpoint and the two names above
secret set GMAIL_TOKEN --host gmail.googleapis.com,pubsub.googleapis.com \
  --token-url https://oauth2.googleapis.com/token \
  --client-id GMAIL_OAUTH_CLIENT_ID --client-secret GMAIL_OAUTH_CLIENT_SECRET
```

`secret set` reads the refresh token hidden, or from stdin, so a consent
script can pipe it in. Better: let secretd run the consent, so the refresh
token never passes through any process of your user:

```bash
secret oauth login GMAIL_TOKEN --google --host gmail.googleapis.com,pubsub.googleapis.com \
  --client-id GMAIL_OAUTH_CLIENT_ID --client-secret GMAIL_OAUTH_CLIENT_SECRET \
  --scope https://www.googleapis.com/auth/gmail.readonly,https://www.googleapis.com/auth/gmail.send,https://www.googleapis.com/auth/pubsub \
  --account agent@example.com
```

`secret oauth login` opens the consent page (loopback redirect on
127.0.0.1, PKCE; `--no-open` prints the link only), receives the code, and
hands it to secretd, which exchanges it at the token endpoint and stores the
refresh token. It stores nothing unless every `--scope` was granted and,
with `--account`, the signed-in account is that one (checked through the
`openid email` scopes, which are added for the check). A token that fails a
check is revoked at `--revoke-url` (set by `--google`). `--google` fills the
three Google endpoints and asks for a refresh token (`access_type=offline`,
`prompt=consent`); other providers take `--auth-url`, `--token-url` and
optionally `--revoke-url`.

In `secrets.yaml` it is an ordinary proxy entry; the app sends requests
without a token, with the API path after `{proxy}` (the first host) or
`{proxy}/pubsub.googleapis.com/...` (another bound host):

```yaml
  GMAIL_TOKEN:
    tier: proxy
    optin: true                        # only for the process that asks for it (below)
    env:
      GMAIL_API_BASE_URL: "{proxy}"    # https://gmail.googleapis.com
```

- The token endpoint, the client id and the client secret are fixed in the
  binding; a request can never pick another. Both referenced names are
  looked up in the secret's project first, then the user scope, at each
  refresh. `secret list` shows `oauth <token host> client-id=... client-secret=...`.
- When the provider refuses the refresh (`invalid_grant`: the account's
  password changed, access was revoked), the proxy answers 502 with a
  message that names the secret and says to give the consent again. It
  never prints the token endpoint's body. Then: `sudo secret rm P/NAME` and
  `secret oauth login` again (or `sudo secret rotate P/NAME` with a new
  refresh token).
- To move an existing run-tier refresh token and client secret into this
  model without a new consent, rebind them (root, values stay):
  `sudo secret bind P/GMAIL_OAUTH_CLIENT_SECRET --host oauth2.googleapis.com --header Authorization --basic-user GMAIL_OAUTH_CLIENT_ID`
  and `sudo secret bind P/GMAIL_TOKEN --host gmail.googleapis.com,pubsub.googleapis.com --token-url https://oauth2.googleapis.com/token --client-id GMAIL_OAUTH_CLIENT_ID --client-secret GMAIL_OAUTH_CLIENT_SECRET`.
- The audit log records each refresh (`"op":"oauth"`, `detail: refresh <host>`),
  never a token. Request bodies up to 16 MiB are kept in memory for the one
  retry; larger bodies are streamed and not retried.

### A secret for one process only

`secret run` gives every entry of `secrets.yaml` to the command. An entry
with `optin: true` is skipped unless the command asks for it, so a mailbox
token reaches the mail worker and not the chat server or the test runner:

```bash
secret run -- pnpm dev                          # everything except opt-in entries
secret run --with GMAIL_TOKEN -- pnpm mail:worker   # plus GMAIL_TOKEN
secret run --only DB_PASSWORD,GMAIL_TOKEN -- pnpm evals   # exactly these two
```

An opt-in entry that has no value in the store does not stop the other
commands. `secret list` in the project marks such entries `opt-in`.

#### A per-run key for a proxy secret

`optin` only hides the variable: the proxy port stays open to any local
process. To make the proxy itself refuse everyone but the run, give the secret
a per-run key. Root sets it once (it is a change to an existing secret):

```bash
/usr/bin/sudo secret bind blackr-business-ai/GMAIL_OAUTH_REFRESH_TOKEN --run-key
secret run --with GMAIL_OAUTH_REFRESH_TOKEN -- pnpm mail:worker
```

At creation, `secret set NAME --host H --header X --run-key` and
`secret oauth login NAME ... --run-key` set it too. `secret list` shows
`run-key` in the USE column. `sudo secret bind P/NAME --no-run-key` turns it
off. A full `bind` keeps the requirement.

- `secret run` gets a random key (32 bytes) from secretd. The `{proxy}` value
  already carries it: `http://127.0.0.1:7777/<project>/<NAME>/rk-<key>/<path>`.
  The proxy removes the `rk-<key>` segment before it forwards the request.
  The key is also in `SECRETD_RUN_KEY`, for an app that prefers a header:
  `X-Secretd-Run-Key: <key>` (the proxy never forwards that header).
- A request without a key gets `401`, one with a wrong, ended or other
  secret's key gets `403`. Both are in the audit log, never with the key.
- The key lives while `secret run` lives: it ends when the command exits,
  also after `kill -9` (the daemon sees the connection close), when you
  `secret lock <project>`, and when secretd restarts (restart the run).
  Keys are in the daemon's memory only; `secret status` shows how many runs
  hold one (`run_keys`).
- A one-off `curl` to the base URL does not work for such a secret. Let a run
  make the call: `secret run --only NAME -- sh -c 'curl "$GMAIL_API_BASE_URL/..."'`.

### Root commands (your own terminal, never inside an agent session)

```bash
/usr/bin/sudo secret reveal my-project/DB_PASSWORD
/usr/bin/sudo secret rotate my-project/DB_PASSWORD
/usr/bin/sudo secret rm my-project/OLD_KEY
/usr/bin/sudo secret bind my-project/KEY --host api.example.com --header x-api-key
/usr/bin/sudo secret export --recipient age1... --out ~/secretd-backup.age
age -d -i ~/your-age-key.txt ~/secretd-backup.age      # read a backup
```

Use the full path `/usr/bin/sudo`: it skips any `sudo` alias or function in
your shell files.

## Limits (read these)

- **Root and the `docker` group** can read everything. A user in the `docker`
  group can mount any host path in a container, so an agent that can run
  `docker` can reach `/var/lib/secretd` and `/etc/secretd`.
- **Run-tier values** are in the memory and the environment of the app, which
  runs as your user. Use dev-only values for them.
- **The proxy has no client authentication** for secrets without a per-run
  key. Any local process can use an unlocked project's such secrets (but not
  read them). Spend limits on each key and the audit log cover this.
  `secret lock` stops use of a project. A user-scope proxy secret is reached
  at `/user/NAME`, so locking a project does not stop direct calls to it;
  `secret lock user` does. A secret with `run_key` needs the key of a live
  `secret run` that listed it.
- **A per-run key does not stop** the run's own child processes (they inherit
  the key in the environment and in the URLs), nor another process of your
  user: it can read `/proc/<pid>/environ` of the run, or start its own
  `secret run --with NAME`. It stops code that calls the port directly
  without being started by `secret run` for that secret (a stray script, an
  agent ability, a prompt-injected tool call outside the run).
- **`secret lock` is not a barrier against an agent**: an agent can run
  `secret unlock`. It stops use that nobody planned.
- **The master key depends on this host** (systemd host key + TPM, no PCR
  binding, so firmware and Secure Boot updates do not lock it). A new disk, a
  reinstall or a cleared TPM loses it, and the store with it: make backups
  with `sudo secret export`.
- A value split across two streamed response chunks is still masked, but the
  proxy holds back up to `len(value)-1` bytes until the next chunk.
- **WebSocket** upgrades go through the proxy: the secret header is added to
  the upgrade request and the `101` response headers are masked. After the
  `101` the bytes flow raw in both directions, so a value the upstream sends
  on the socket itself is not masked. An OAuth binding works the same way:
  the access token goes on the upgrade request.
- **OAuth access tokens** live in the daemon's memory until they expire, and
  the proxy masks the current and the previous one. A token that an
  upstream echoes long after a refresh is not recognised.
- Values that were committed to git stay in the git history: rotate them.

## Development

```bash
go test ./...
bash scripts/e2e.sh     # daemon + CLI end to end, no root needed
```
