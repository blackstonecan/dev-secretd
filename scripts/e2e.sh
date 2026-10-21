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

# --- root and audit ---
check "root commands need sudo" "needs root" "$("$secret" reveal demo/DB_PASSWORD 2>&1 || true)"
if grep -q 'pw-123\|sk-fake\|sk_test_abc' "$work/state/audit.log"; then fail "audit log has a value"; else ok "audit log has no values"; fi
check "audit log written" '"op":"resolve"' "$(cat "$work/state/audit.log")"
if grep -aq 'pw-123\|sk-fake' "$work/state/store.enc"; then fail "store file has plaintext"; else ok "store file is encrypted"; fi

echo "all $pass checks passed"
