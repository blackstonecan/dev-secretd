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
printf '{"socket": "%s", "proxy_addr": "127.0.0.1:%s", "state_dir": "%s", "master_cred": "%s", "allow_uid": %s, "basic_user": "e2e-user"}\n' \
  "$work/api.sock" "$port" "$work/state" "$work/unused.cred" "$(id -u)" > "$work/config.json"
# The same daemon, seen through a config without a default --basic username.
sed 's/, "basic_user": "e2e-user"//' "$work/config.json" > "$work/config-nobasic.json"
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
check "set: hosts + --basic"    "stored demo/GIT_TOKEN"   "$(printf 'git-tok' | "$secret" set GIT_TOKEN --host api.example.com,git.example.com --header Authorization --basic)"
check "list: hosts and basic"   "api.example.com,git.example.com header Authorization basic e2e-user" "$("$secret" list | grep demo/GIT_TOKEN)"
check "set: --basic-user"       "basic other-user"        "$(printf 'git-tok2' | "$secret" set GIT_TOKEN2 --host git.example.com --header Authorization --basic-user other-user >/dev/null && "$secret" list | grep demo/GIT_TOKEN2)"
check "basic needs a default"   "no default username"     "$(printf 'x' | SECRETD_CONFIG="$work/config-nobasic.json" "$secret" set GIT_TOKEN3 --host git.example.com --header Authorization --basic 2>&1 || true)"
check "basic needs proxy tier"  "for proxy-tier secrets"  "$(printf 'x' | "$secret" set GIT_TOKEN4 --basic 2>&1 || true)"
check "basic and format refused" "--basic needs --header and no --format" "$(printf 'x' | "$secret" set GIT_TOKEN5 --host a.example.com --header Authorization --format 'Bearer {}' --basic 2>&1 || true)"
check "duplicate host refused"  "listed twice"            "$(printf 'x' | "$secret" set GIT_TOKEN6 --host a.example.com,A.example.com --header x 2>&1 || true)"

# --- root and audit ---
check "root commands need sudo" "needs root" "$("$secret" reveal demo/DB_PASSWORD 2>&1 || true)"
if grep -q 'pw-123\|sk-fake\|sk_test_abc\|npm-user\|gh-user\|npm-fb\|ghd-user\|ghd-client\|git-tok' "$work/state/audit.log"; then fail "audit log has a value"; else ok "audit log has no values"; fi
check "audit: fallback recorded" '"detail":"run from user"' "$(cat "$work/state/audit.log")"
check "audit log written" '"op":"resolve"' "$(cat "$work/state/audit.log")"
if grep -aq 'pw-123\|sk-fake' "$work/state/store.enc"; then fail "store file has plaintext"; else ok "store file is encrypted"; fi

echo "all $pass checks passed"
