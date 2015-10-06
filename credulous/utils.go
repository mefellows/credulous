package credulous

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

func Panic_the_err(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		os.Exit(1)
	}
}

func Ensure_directory(path string) {
	if path == "" {
		panic(errors.New("Can't ensure empty string as a directory!"))
	}

	err := os.MkdirAll(path, 0755)
	Panic_the_err(err)
}

func GetRootPath() string {
	rootPath := MakePath(Config.Home + "/.credulous")
	os.MkdirAll(rootPath, 0700)
	return rootPath
}

func MakePath(path string) string {
	if runtime.GOOS == "windows" {
		return strings.Replace(path, "/", "\\", -1)
	}
	return path
}
