#!/usr/bin/env bash
# End-to-end test without root: a daemon with a temporary config and key, and
# the real CLI. Values here are fake. Run: bash scripts/e2e.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'kill "${daemon_pid:-0}" 2>/dev/null || true; rm -rf "$work"' EXIT

go build -o "$work/bin/" "$root/cmd/..."
secret="$work/bin/secret"
mkdir -p "$work/state" "$work/project" "$work/tier" "$work/app"
port=$(( 20000 + RANDOM % 20000 ))
openssl rand -hex 32 > "$work/master.key"
printf '{"socket": "%s", "proxy_addr": "127.0.0.1:%s", "state_dir": "%s", "master_cred": "%s", "allow_uid": %s}\n' \
  "$work/api.sock" "$port" "$work/state" "$work/unused.cred" "$(id -u)" > "$work/config.json"
export SECRETD_CONFIG="$work/config.json"

"$work/bin/secretd" --config "$work/config.json" --master-key-file "$work/master.key" 2>"$work/daemon.log" &
daemon_pid=$!
for _ in $(seq 50); do [[ -S $work/api.sock ]] && break; sleep 0.1; done

pass=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
fail() { echo "FAIL $1"; exit 1; }
check() { # check NAME EXPECTED ACTUAL
  [[ "$3" == *"$2"* ]] && ok "$1" || fail "$1: expected [$2], got [$3]"
}

# --- set, list ---
cd "$work/project"
check "init"               "made secrets.yaml"       "$("$secret" init --project demo)"
check "set run"            "stored demo/DB_PASSWORD" "$(printf 'pw-123\n' | "$secret" set DB_PASSWORD)"
check "set proxy"          "tier proxy"              "$(printf 'sk-fake' | "$secret" set API_KEY --host api.example.com --header x-api-key)"
check "set file"           "stored demo/SA_JSON"     "$(printf '{"k":1}' | "$secret" set SA_JSON --file)"
check "set is create-only" "already exists"          "$(printf 'other' | "$secret" set DB_PASSWORD 2>&1 || true)"
list="$("$secret" list)"
check "list shows binding" "api.example.com header x-api-key" "$list"
[[ "$list" != *sk-fake* && "$list" != *pw-123* ]] && ok "list has no values" || fail "list has values"

# --- run ---
printf '%s\n' 'project: demo' 'secrets:' \
  '  API_KEY:' '    tier: proxy' '    env:' '      EXAMPLE_BASE_URL: "{proxy}"' '      EXAMPLE_API_KEY: placeholder' \
  '  DB_PASSWORD:' '    tier: run' \
  '  SA_JSON:' '    tier: run' '    var: GOOGLE_APPLICATION_CREDENTIALS' > secrets.yaml
out="$("$secret" run -- sh -c 'echo "$DB_PASSWORD|$EXAMPLE_BASE_URL|$EXAMPLE_API_KEY|$(cat "$GOOGLE_APPLICATION_CREDENTIALS")|$GOOGLE_APPLICATION_CREDENTIALS"')"
check "run: run-tier value"   "pw-123|"                               "$out"
check "run: proxy URL"        "|http://127.0.0.1:$port/demo/API_KEY|" "$out"
check "run: placeholder only" "|placeholder|"                         "$out"
[[ "$out" != *sk-fake* ]] && ok "run: proxy value not in env" || fail "proxy value in env"
check "run: file secret"      '|{"k":1}|'                             "$out"
[[ ! -e "${out##*|}" ]] && ok "run: file removed after exit" || fail "file secret left on disk"
set +e; "$secret" run -- sh -c 'exit 7'; code=$?; set -e
[[ $code -eq 7 ]] && ok "run: exit code passed on" || fail "exit code $code"

# A manifest that claims run tier for a proxy secret must not get the value.
cd "$work/tier"
printf '%s\n' 'project: demo' 'secrets:' '  API_KEY:' '    tier: run' > secrets.yaml
check "manifest cannot change tier" "the store says proxy" "$("$secret" run -- true 2>&1 || true)"

# --- proxy refusals (the unit tests cover forwarding) ---
check "proxy: run-tier refused" "not a proxy-tier secret" "$(curl -s "http://127.0.0.1:$port/demo/DB_PASSWORD/x")"

# --- lock ---
cd "$work/project"
check "lock"               "locked=true"   "$("$secret" lock demo)"
check "locked run fails"   "is locked"     "$("$secret" run -- true 2>&1 || true)"
check "locked proxy fails" "is locked"     "$(curl -s "http://127.0.0.1:$port/demo/API_KEY/x")"
check "status"             "locked:  demo" "$("$secret" status)"
check "unlock"             "locked=false"  "$("$secret" unlock demo)"

# --- import ---
cd "$work/app"
printf '%s\n' 'PORT=3000' 'STRIPE_KEY=sk_test_abc' 'export JWT_SECRET="j w t"' > .env
check "import"             "moved 2 key(s)" "$("$secret" import .env --project app --keep PORT --yes)"
env_now="$(cat .env)"
check "import: config kept" "PORT=3000" "$env_now"
[[ "$env_now" != *sk_test_abc* && "$env_now" != *"j w t"* ]] && ok "import: values removed from .env" || fail ".env still has values"
check "import: manifest"   "JWT_SECRET"        "$(cat secrets.yaml)"
check "import: run works"  "sk_test_abc|j w t" "$("$secret" run -- sh -c 'echo "$STRIPE_KEY|$JWT_SECRET"')"

# --- user scope ---
export XDG_CONFIG_HOME="$work/cfg"
mkdir -p "$work/fb" "$work/nofb" "$work/elsewhere"
check "set --user"            "stored user/NPM_TOKEN"    "$(printf 'npm-user' | "$secret" set NPM_TOKEN --user)"
check "set --user proxy"      "stored user/GH_TOKEN"     "$(printf 'gh-user' | "$secret" set GH_TOKEN --user --host api.github.com --header Authorization --format 'Bearer {}')"
check "init --project user"   "user scope, not a project" "$("$secret" init --project user 2>&1 || true)"
cd "$work/fb"
printf '%s\n' 'project: fb' 'secrets:' \
  '  NPM_TOKEN:' '    tier: run' '    fallback: user' \
  '  GH_TOKEN:' '    tier: proxy' '    fallback: user' '    env:' '      GH_BASE: "{proxy}"' > secrets.yaml
out="$("$secret" run -- sh -c 'echo "$NPM_TOKEN|$GH_BASE"' 2>"$work/run.err")"
check "fallback: run value"    "npm-user|"                                  "$out"
check "fallback: proxy URL"    "|http://127.0.0.1:$port/user/GH_TOKEN"      "$out"
check "fallback: stderr note"  "secret: NPM_TOKEN from user"                "$(cat "$work/run.err")"
check "list: fallback shown"   "fallback"                                   "$("$secret" list | grep user/NPM_TOKEN)"
check "project secret added"   "stored fb/NPM_TOKEN"                        "$(printf 'npm-fb' | "$secret" set NPM_TOKEN)"
check "project secret wins"    "npm-fb"                                     "$("$secret" run -- sh -c 'echo "$NPM_TOKEN"' 2>/dev/null)"
check "list: overridden shown" "overridden by fb"                           "$("$secret" list | grep user/NPM_TOKEN)"
cd "$work/nofb"
printf '%s\n' 'project: nofb' 'secrets:' '  NPM_TOKEN:' '    tier: run' > secrets.yaml
check "no fallback without opt-in" "no secret nofb/NPM_TOKEN" "$("$secret" run -- true 2>&1 || true)"
check "lock user"              "locked=true"         "$("$secret" lock user)"
cd "$work/fb"
check "locked user: fallback refused" "project user is locked" "$("$secret" run -- true 2>&1 || true)"
mkdir -p "$work/fbown" && cd "$work/fbown"
printf '%s\n' 'project: fb' 'secrets:' '  NPM_TOKEN:' '    tier: run' '    fallback: user' > secrets.yaml
check "locked user: own secret works" "npm-fb"       "$("$secret" run -- sh -c 'echo "$NPM_TOKEN"')"
check "locked user: proxy refused"    "is locked"    "$(curl -s "http://127.0.0.1:$port/user/GH_TOKEN/x")"
check "unlock user"            "locked=false"        "$("$secret" unlock user)"
cd "$work/elsewhere"
check "run --user needs manifest" "secret init --user" "$("$secret" run --user -- true 2>&1 || true)"
check "init --user"            "user.yaml"           "$("$secret" init --user)"
printf '%s\n' 'project: user' 'secrets:' '  NPM_TOKEN:' '    tier: run' > "$XDG_CONFIG_HOME/secretd/user.yaml"
check "run --user"             "npm-user"            "$("$secret" run --user -- sh -c 'echo "$NPM_TOKEN"')"
check "user value unchanged"   "npm-user"            "$(cd "$work/fb" && rm secrets.yaml && printf '%s\n' 'project: fb2' 'secrets:' '  NPM_TOKEN:' '    tier: run' '    fallback: user' > secrets.yaml && "$secret" run -- sh -c 'echo "$NPM_TOKEN"' 2>/dev/null)"

# --- user-scope defaults ---
mkdir -p "$work/dflt" "$work/client"
check "set --default needs --user" "add --user"          "$(printf 'x' | "$secret" set GH_DEFAULT --default 2>&1 || true)"
check "set --user --default"       "it is a default"     "$(printf 'ghd-user' | "$secret" set GH_DEFAULT --user --default)"
check "list --all marks default"   "default for all projects" "$("$secret" list --all | grep user/GH_DEFAULT)"
cd "$work/dflt"
printf '%s\n' 'project: dflt' 'secrets:' '  GH_DEFAULT:' '    tier: run' > secrets.yaml
check "default: no fallback line"  "ghd-user"            "$("$secret" run -- sh -c 'echo "$GH_DEFAULT"' 2>/dev/null)"
check "default: stderr note"       "GH_DEFAULT from user" "$("$secret" run -- true 2>&1)"
check "list: default shown"        "default"             "$("$secret" list | grep user/GH_DEFAULT)"
cd "$work/client"
printf '%s\n' 'project: client' 'secrets:' '  GH_DEFAULT:' '    tier: run' '    fallback: none' > secrets.yaml
check "fallback none refuses default" "no secret client/GH_DEFAULT" "$("$secret" run -- true 2>&1 || true)"
check "client adds its own"        "stored client/GH_DEFAULT" "$(printf 'ghd-client' | "$secret" set GH_DEFAULT)"
check "client uses its own"        "ghd-client"          "$("$secret" run -- sh -c 'echo "$GH_DEFAULT"')"
check "bind --default needs root"  "needs root"          "$("$secret" bind user/GH_DEFAULT --no-default 2>&1 || true)"

# --- several hosts, Basic auth ---
cd "$work/project"
check "set: hosts + --basic-user" "stored demo/GIT_TOKEN"   "$(printf 'git-tok' | "$secret" set GIT_TOKEN --host api.example.com,git.example.com --header Authorization --basic-user E2E_USERNAME)"
check "list: hosts and basic"   "api.example.com,git.example.com header Authorization basic user=E2E_USERNAME" "$("$secret" list | grep demo/GIT_TOKEN)"
check "proxy: username missing" "basic username E2E_USERNAME" "$(curl -s "http://127.0.0.1:$port/demo/GIT_TOKEN/x")"
check "basic-user names a value" "UPPER_SNAKE_CASE"        "$(printf 'x' | "$secret" set GIT_TOKEN2 --host git.example.com --header Authorization --basic-user someone 2>&1 || true)"
check "basic needs proxy tier"  "for proxy-tier secrets"  "$(printf 'x' | "$secret" set GIT_TOKEN4 --basic 2>&1 || true)"
check "basic and format refused" "--basic needs --header and no --format" "$(printf 'x' | "$secret" set GIT_TOKEN5 --host a.example.com --header Authorization --format 'Bearer {}' --basic 2>&1 || true)"
check "duplicate host refused"  "listed twice"            "$(printf 'x' | "$secret" set GIT_TOKEN6 --host a.example.com,A.example.com --header x 2>&1 || true)"
check "set: plain --basic"      "stored demo/GIT_TOKEN7"  "$(printf 'git-tok' | "$secret" set GIT_TOKEN7 --host git.example.com --header Authorization --basic)"
list7="$("$secret" list | grep demo/GIT_TOKEN7)"
check "list: plain basic"       "header Authorization basic" "$list7"
[[ "$list7" != *user=* ]] && ok "plain basic names no value" || fail "plain basic shows a username link"

# --- public values ---
mkdir -p "$work/pub" && cd "$work/pub"
printf '%s\n' 'project: pub' 'secrets:' '  E2E_USERNAME:' '    tier: public' '  E2E_ORG:' '    tier: public' '    var: ORG' > secrets.yaml
check "public: set (user)"      "set user/E2E_USERNAME = e2e-user (public)" "$("$secret" set E2E_USERNAME e2e-user --user --public)"
check "public: change, no root" "= e2e-user2"             "$("$secret" set E2E_USERNAME e2e-user2 --user --public)"
check "public: get falls back"  "e2e-user2"               "$("$secret" get E2E_USERNAME)"
check "public: list shows it"   "= e2e-user2"             "$("$secret" list --all | grep user/E2E_USERNAME)"
check "public: list fallback"   "fallback"                "$("$secret" list | grep user/E2E_USERNAME)"
check "public: stdin value"     "set pub/E2E_ORG = acme"  "$(printf 'acme\n' | "$secret" set E2E_ORG --public)"
check "public: run env"         "e2e-user2|acme"          "$("$secret" run -- sh -c 'echo "$E2E_USERNAME|$ORG"' 2>/dev/null)"
check "public: project wins"    "pub-bot"                 "$("$secret" set E2E_USERNAME pub-bot --public >/dev/null && "$secret" get E2E_USERNAME)"
check "public: user unchanged"  "e2e-user2"               "$("$secret" get E2E_USERNAME --user)"
check "value arg needs --public" "for --public values only" "$("$secret" set SOME_TOKEN typed-value 2>&1 || true)"
check "public cannot replace private" "a name is either private or public" "$("$secret" set NPM_TOKEN x --user --public 2>&1 || true)"
check "get refuses private"     "is a private secret"     "$("$secret" get NPM_TOKEN --user 2>&1 || true)"
printf '%s\n' 'project: pub' 'secrets:' '  NPM_TOKEN:' '    tier: public' > "$work/pub/secrets.yaml"
check "manifest cannot make private public" "the store says run" "$("$secret" run -- true 2>&1 || true)"
check "bind refuses public"     "needs root"              "$("$secret" bind user/E2E_USERNAME --run 2>&1 || true)"

# --- secret git (a customer's repo) ---
# A throwaway global git config, so the user's real one is never read or changed.
export GIT_CONFIG_GLOBAL="$work/gitconfig" GIT_CONFIG_NOSYSTEM=1
git config --global url."http://127.0.0.1:$port/user/GITHUB_TOKEN/github.com/mine/".insteadOf "https://github.com/mine/"
mkdir -p "$work/cust" "$work/mine" "$work/sshrepo" && cd "$work/cust"
git init -q && git remote add origin https://github.com/acme/app.git && git remote add upstream https://github.com/other/lib.git
check "git: needs secrets.yaml" "secret init --project" "$("$secret" git --no-check 2>&1 || true)"
"$secret" init --project cust >/dev/null
check "git: needs the project's token" "has no GITHUB_TOKEN of its own" "$("$secret" git --no-check 2>&1 || true)"
printf 'x' | "$secret" set API_ONLY --host api.github.com --header Authorization --basic >/dev/null
check "git: token must reach github.com" "not bound to github.com" "$("$secret" git --secret API_ONLY --no-check 2>&1 || true)"
printf 'cust-tok' | "$secret" set GITHUB_TOKEN --host api.github.com,github.com --header Authorization --basic >/dev/null
check "git: rule added"         "through cust/GITHUB_TOKEN" "$("$secret" git --no-check)"
check "git: origin rewritten"   "http://127.0.0.1:$port/cust/GITHUB_TOKEN/github.com/acme/app.git" "$(git remote get-url --push origin)"
check "git: other owner untouched" "https://github.com/other/lib.git" "$(git remote get-url upstream)"
[[ -z "$(git config --global --get-regexp 'cust/GITHUB_TOKEN' || true)" ]] && ok "git: rule is local only" || fail "git: rule written to the global config"
check "git: off"                "removed rule https://github.com/acme/" "$("$secret" git --off)"
check "git: origin back"        "https://github.com/acme/app.git" "$(git remote get-url origin)"
check "git: off when none"      "no secretd rule"         "$("$secret" git --off)"
cd "$work/mine" && git init -q && git remote add origin https://github.com/mine/repo.git && "$secret" init --project mine >/dev/null
check "git: own account refused" "covered by your global rule" "$("$secret" git --no-check 2>&1 || true)"
cd "$work/sshrepo" && git init -q && git remote add origin git@github.com:acme/app.git && "$secret" init --project sshrepo >/dev/null
check "git: SSH remote refused" "uses SSH"                "$("$secret" git --no-check 2>&1 || true)"
unset GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM

# --- root and audit ---
check "root commands need sudo" "needs root" "$("$secret" reveal demo/DB_PASSWORD 2>&1 || true)"
if grep -q 'pw-123\|sk-fake\|sk_test_abc\|npm-user\|gh-user\|npm-fb\|ghd-user\|ghd-client\|git-tok\|cust-tok' "$work/state/audit.log"; then fail "audit log has a value"; else ok "audit log has no values"; fi
check "audit: fallback recorded" '"detail":"run from user"' "$(cat "$work/state/audit.log")"
check "audit log written" '"op":"resolve"' "$(cat "$work/state/audit.log")"
if grep -aq 'pw-123\|sk-fake' "$work/state/store.enc"; then fail "store file has plaintext"; else ok "store file is encrypted"; fi

echo "all $pass checks passed"
