// secret is the CLI of secretd.
//
// User commands (your user and your agents): init, set, list, run, import,
// lock, unlock, status. They can add secrets and use them, never read
// proxy-tier values.
//
// Root commands (sudo, your password every time): reveal, rotate, rm, bind,
// export. They work on the store file directly.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const usage = `secret - store secrets that agents can use but not see

User commands:
  secret init --project NAME              make secrets.yaml in this folder
  secret init --user                      make the user manifest (~/.config/secretd/user.yaml)
  secret set NAME [flags]                 add a new secret (hidden input or stdin)
  secret set NAME VALUE --public          add or change a public value (not secret: anyone
                                          can read it; a project without its own uses the user's)
      --project P      default: from secrets.yaml
      --user           user scope: projects use it with "fallback: user"
                       in secrets.yaml; their own secret of the name wins
      --default        with --user: every project that lists the name gets
                       it (unless it has its own or says "fallback: none")
      --file           run-tier file secret (the env var holds a temp file path)
      --host H[,H2]    proxy tier: upstream host (HTTPS); more hosts, comma-separated:
                       /P/NAME/<path> goes to the first, /P/NAME/H2/<path> to H2
      --header X       proxy tier: header name, for example x-api-key
      --format F       proxy tier: header template, for example "Bearer {}"
      --basic NAME     proxy tier: header value "Basic base64(USER:secret)", USER is the
                       public value NAME (git over HTTPS needs it)
      --query Q        proxy tier: query parameter, instead of a header
  secret get NAME [--project P | --user]  print a public value (the project's, else the user's)
  secret list [--project P | --all]       names and rules; values of public entries only
  secret run [--project P] -- CMD...      run CMD with the secrets of secrets.yaml
  secret run --user -- CMD...             run CMD with the secrets of the user manifest
  secret import FILE [--keep K1,K2] [--yes]
                                          move values from a .env file into secretd
  secret lock [P] | secret unlock [P]     block or allow use of a project
                                          ("user" blocks every use of user-scope secrets)
  secret status

Root commands (run with: /usr/bin/sudo secret ...):
  reveal P/NAME        print a value (run it in your own terminal, not in an agent)
  rotate P/NAME        replace a value
  rm P/NAME            delete a secret
  bind P/NAME [--host H[,H2] --header X [--format F | --basic NAME] | --query Q | --run [--file]]
                       change the tier or the binding (private and public never convert)
  bind user/NAME --default | --no-default
                       make a user-scope secret a default for all projects, or not
  export --recipient AGE_PUBLIC_KEY --out FILE
                       encrypted backup of all secrets (decrypt with age)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "set":
		err = cmdSet(args)
	case "get":
		err = cmdGet(args)
	case "list":
		err = cmdList(args)
	case "run":
		var code int
		code, err = cmdRun(args)
		if err == nil {
			os.Exit(code)
		}
	case "import":
		err = cmdImport(args)
	case "lock", "unlock":
		err = cmdLock(args, cmd == "lock")
	case "status":
		err = cmdStatus()
	case "reveal", "rotate", "rm", "bind", "export":
		err = rootCommand(cmd, args)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		err = fmt.Errorf("unknown command %q (see `secret help`)", cmd)
	}
	if err != nil {
		var ue usageError
		fmt.Fprintln(os.Stderr, "secret:", err)
		if errors.As(err, &ue) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

// splitKey turns "project/NAME" into its parts.
func splitKey(s string) (string, string, error) {
	p, n, ok := strings.Cut(s, "/")
	if !ok || p == "" || n == "" {
		return "", "", usageError{fmt.Sprintf("want PROJECT/NAME, got %q", s)}
	}
	return p, n, nil
}
