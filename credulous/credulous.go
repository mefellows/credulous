package credulous

import (
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

const ENV_PATTERN string = "^[A-Za-z_][A-Za-z0-9_]*=.*"

type CredulousConfig struct {
	EnvVarTemplate string
	Home           string
}

var Config CredulousConfig

// Setup defaults
const FORMAT_WINDOWS_ENV_VARS string = `$env:%s="%s"\n`
const FORMAT_LINUX_ENV_VARS string = `export %s="%s"\n`

func init() {
	if runtime.GOOS == "windows" {
		Config = CredulousConfig{
			Home:           os.Getenv("USERPROFILE"),
			EnvVarTemplate: FORMAT_WINDOWS_ENV_VARS,
		}
	} else {
		Config = CredulousConfig{
			Home:           os.Getenv("HOME"),
			EnvVarTemplate: FORMAT_WINDOWS_ENV_VARS,
		}
	}
}

type Account struct {
	Username string
	Account  string
}

func GetAccounts() []Account {
	rootDir, err := os.Open(GetRootPath())
	if err != nil {
		Panic_the_err(err)
	}
	set, err := ListAvailableCredentials(rootDir)

	accounts := make([]Account, len(set))
	for i, acct := range set {
		tmp := strings.Split(acct, "@")
		accounts[i] = Account{tmp[0], tmp[1]}
	}
	if err != nil {
		return nil
	}
	return accounts
}

func GetCredentials(username string, account string) (string, string, error) {
	keyfile := GetPrivateKey("")

	repo, err := ParseRepoArgs("local")
	if err != nil {
		return "", "", err
	}
	creds, err := RetrieveCredentials(repo, account, username, keyfile)

	// TODO: validate?
	/*
		if err != nil && validate {
			err = creds.ValidateCredentials(account, username)
		}
	*/
	return creds.Encryptions[0].decoded.KeyId, creds.Encryptions[0].decoded.SecretKey, err
}

func GetPrivateKey(filename string) string {
	if filename == "" {
		filename = MakePath(filepath.Join(Config.Home, "/.ssh/id_rsa"))
	} else {
		filename = filename
	}
	return filename
}

func ParseRepoArgs(repo string) (string, error) {
	// the default is 'local' which is set below, so not much to do here
	if repo == "local" {
		repo = path.Join(GetRootPath(), "local")
	} else {
		repo = repo
	}
	return repo, nil
}
