package config

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// The master key is 32 random bytes, stored as 64 hex characters inside a
// systemd-creds file (encrypted with the host key and the TPM when present).

// DaemonKey reads the key that systemd gives the service through
// LoadCredentialEncrypted=master:... ; keyFile overrides it (tests only).
func DaemonKey(keyFile string) ([]byte, error) {
	if keyFile == "" {
		dir := os.Getenv("CREDENTIALS_DIRECTORY")
		if dir == "" {
			return nil, fmt.Errorf("CREDENTIALS_DIRECTORY is not set: start secretd through systemd, or pass --master-key-file")
		}
		keyFile = filepath.Join(dir, "master")
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return decodeKey(raw)
}

// RootKey decrypts the credential file. Only root can do this.
func RootKey(credFile string) ([]byte, error) {
	var out, errb bytes.Buffer
	cmd := exec.Command("systemd-creds", "decrypt", "--name=master", credFile, "-")
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("systemd-creds decrypt: %v: %s", err, bytes.TrimSpace(errb.Bytes()))
	}
	return decodeKey(out.Bytes())
}

func decodeKey(raw []byte) ([]byte, error) {
	key, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("master key must be 64 hex characters")
	}
	return key, nil
}
