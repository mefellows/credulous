package credulous

import (
	"fmt"
	"os"
	"runtime"
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
	fmt.Printf("Path: %s", Config.Home)
}

// Func GetAccounts

// Func Getcredulous.Credentials(account)
func GetAccounts() []string {
	fmt.Printf("Accounts")
	rootDir, err := os.Open(GetRootPath())
	if err != nil {
		Panic_the_err(err)
	}
	set, err := ListAvailableCredentials(rootDir)
	if err != nil {
		return nil
	}
	return set
}
func GetCredentials() {}
