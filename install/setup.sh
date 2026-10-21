#!/usr/bin/env bash
# Install or remove secretd. Build first as your user (bash scripts/build.sh),
# then run this yourself:
#
#   sudo bash install/setup.sh              install or update
#   sudo bash install/setup.sh --uninstall  remove the service, binaries and sudoers rule
#                                           (keeps the master key and the store)
#   sudo bash install/setup.sh --purge      also delete the master key and the store
#   sudo bash install/setup.sh --new-key    make a new master key (only while the store is empty)
#
# What install does:
#   - makes the system user devsecrets (no login, no home)
#   - installs dist/secret and dist/secretd to /usr/local/bin (owned by root)
#   - writes /etc/secretd/config.json (allow_uid = the user who ran sudo)
#   - makes the master key once: 32 random bytes, encrypted with systemd-creds
#     (host key + TPM when present) to /etc/secretd/master.cred
#   - installs the sudoers rule (password every time for `sudo secret`)
#   - installs and starts secretd.service
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "run with sudo"
user=${SUDO_USER:?run with sudo, not as root}
uid=$(id -u "$user")
src="$(cd "$(dirname "$0")/.." && pwd)"

uninstall() {
  systemctl disable --now secretd.service 2>/dev/null || true
  rm -f /etc/systemd/system/secretd.service /etc/sudoers.d/secretd \
        /usr/local/bin/secret /usr/local/bin/secretd
  systemctl daemon-reload
  echo "removed the service, the binaries and the sudoers rule"
}

case "${1:-}" in
  --uninstall)
    uninstall
    echo "kept /etc/secretd (master key) and /var/lib/secretd (store)"
    exit 0 ;;
  --purge)
    uninstall
    read -r -p "Delete the master key and ALL stored secrets? Type 'delete': " answer
    [[ $answer == delete ]] || die "stopped"
    rm -rf /etc/secretd /var/lib/secretd
    userdel devsecrets 2>/dev/null || true
    echo "purged"
    exit 0 ;;
  --new-key)
    [[ -e /var/lib/secretd/store.enc ]] && die "the store has secrets: a new key would make them unreadable"
    rm -f /etc/secretd/master.cred
    echo "removed the old master key; making a new one" ;;
  "") ;;
  *) die "unknown option $1" ;;
esac

for bin in secret secretd; do
  [[ -f $src/dist/$bin ]] || die "missing $src/dist/$bin: run 'bash scripts/build.sh' as $user first"
done
command -v systemd-creds >/dev/null || die "systemd-creds not found"

# 1. System user
if ! id devsecrets >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin devsecrets
  echo "made system user devsecrets"
fi

# 2. Binaries, owned by root, so your user (and agents) cannot replace them
install -o root -g root -m 0755 "$src/dist/secret" /usr/local/bin/secret
install -o root -g root -m 0755 "$src/dist/secretd" /usr/local/bin/secretd

# 3. Config (no secrets in it)
install -d -o root -g root -m 0755 /etc/secretd
printf '{\n  "socket": "/run/secretd/api.sock",\n  "proxy_addr": "127.0.0.1:7777",\n  "state_dir": "/var/lib/secretd",\n  "master_cred": "/etc/secretd/master.cred",\n  "allow_uid": %s\n}\n' \
  "$uid" > /etc/secretd/config.json
chmod 0644 /etc/secretd/config.json

# 4. Master key, once. Losing it (or the TPM/host key) makes the store unreadable:
#    keep backups with `sudo secret export`.
#    Bound to the host key and the TPM (when present), but to no PCRs: a
#    Secure Boot change or a firmware/dbx update must not lock the store.
if [[ ! -f /etc/secretd/master.cred ]]; then
  umask 077
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' \
    | systemd-creds encrypt --name=master --with-key=auto --tpm2-pcrs= - /etc/secretd/master.cred
  chmod 0600 /etc/secretd/master.cred
  echo "made the master key: /etc/secretd/master.cred"
fi

# 5. sudoers rule, checked before it is installed
tmp=$(mktemp)
cp "$src/install/sudoers" "$tmp"
visudo -cf "$tmp" >/dev/null || { rm -f "$tmp"; die "sudoers rule failed the visudo check"; }
install -o root -g root -m 0440 "$tmp" /etc/sudoers.d/secretd
rm -f "$tmp"

# 6. Service
install -o root -g root -m 0644 "$src/install/secretd.service" /etc/systemd/system/secretd.service
systemctl daemon-reload
systemctl enable secretd.service >/dev/null
systemctl restart secretd.service
sleep 1
systemctl --no-pager --lines=5 status secretd.service || die "secretd did not start: journalctl -u secretd"

echo
echo "secretd is installed. As $user, try: secret status"
