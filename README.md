# secretd

Store secrets that agents can **use** but cannot **see**. One store for all
projects on this machine. Your user (and every agent that runs as your user)
can add secrets and use them; only root (you, with `sudo` and your password)
can read, change or delete them.

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

### Three tiers

| Tier | For | The app gets | Can an agent see the value? |
|---|---|---|---|
| **proxy** | HTTP API keys | a local base URL + a placeholder key | **No** |
| **run** | values the app must hold (DB password, JWT key, a JSON key file) | env var, or a temp file in `$XDG_RUNTIME_DIR` (RAM), removed at exit | In theory yes (same user). **Use dev-only values.** |
| plain `.env` | config that is not secret (ports, URLs) | the normal `.env` | Yes, and that is fine |

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
  and on the proxy; projects' own secrets keep working.
- Outside projects: `secret init --user` makes `~/.config/secretd/user.yaml`
  (`project: user`); list secrets there and use `secret run --user -- CMD`.

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
- **The proxy has no client authentication.** Any local process can use an
  unlocked project's proxy secrets (but not read them). Spend limits on each
  key and the audit log cover this. `secret lock` stops use of a project.
  A user-scope proxy secret is reached at `/user/NAME`, so locking a project
  does not stop direct calls to it; `secret lock user` does.
- **`secret lock` is not a barrier against an agent**: an agent can run
  `secret unlock`. It stops use that nobody planned.
- **The master key depends on this host** (systemd host key + TPM, no PCR
  binding, so firmware and Secure Boot updates do not lock it). A new disk, a
  reinstall or a cleared TPM loses it, and the store with it: make backups
  with `sudo secret export`.
- A value split across two streamed response chunks is still masked, but the
  proxy holds back up to `len(value)-1` bytes until the next chunk.
- Values that were committed to git stay in the git history: rotate them.

## Development

```bash
go test ./...
bash scripts/e2e.sh     # daemon + CLI end to end, no root needed
```
