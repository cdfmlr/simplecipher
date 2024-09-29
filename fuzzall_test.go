package simplecipher

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// This file provides a TestAllFuzz(*testing.T) that runs all
// FuzzTests(*testing.F) found in current directory.
//
// This makes `go test ./...` running all fuzz tests in a reasonable duration,
// instead of only running the seed cases.

// findTestFiles walks through the current directory and returns all *_test.go files.
// Returns a list of file paths.
func findTestFiles() ([]string, error) {
	var testFiles []string

	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			testFiles = append(testFiles, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return testFiles, nil
}

// findFuzzTestFuncs scans the given file and returns all fuzz test function names.
func findFuzzTestFuncs(path string) ([]string, error) {
	var fuzzFuncs []string

	// notice to add Fuzz prefix back to get the full function name
	nameReg := regexp.MustCompile(`func Fuzz(\w+)\(f \*testing.F\)`)

	file, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "func Fuzz") {
			matches := nameReg.FindStringSubmatch(line)
			if len(matches) == 2 {
				fuzzFuncs = append(fuzzFuncs, "Fuzz"+matches[1])
			}
		}
	}

	return fuzzFuncs, nil
}

// findAllFuzzTest finds all fuzz test names from all test files.
func findAllFuzzTest() ([]string, error) {
	testFiles, err := findTestFiles()
	if err != nil {
		return nil, err
	}

	allFuzzFuncs := make([]string, 0)

	for _, file := range testFiles {
		fuzzFuncs, err := findFuzzTestFuncs(file)
		if err != nil {
			return nil, err
		}

		allFuzzFuncs = append(allFuzzFuncs, fuzzFuncs...)
	}

	return allFuzzFuncs, nil
}

// runFuzz runs the fuzz test with the given name and duration.
func runFuzz(f string, fuzzTime time.Duration) error {
	cmd := exec.Command("go", "test", "-v", ".",
		"-run", f,
		"-fuzz", f,
		"-fuzztime", fuzzTime.String())

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// TestAllFuzz runs all fuzz tests found in the test files.
func TestAllFuzz(t *testing.T) {
	fuzzFuncs, err := findAllFuzzTest()
	if err != nil {
		t.Fatal("failed to find fuzz test funcs:", err)
	}
	t.Logf("Found %v fuzz tests: %v", len(fuzzFuncs), fuzzFuncs)

	fuzzTime := 10 * time.Second

	for _, f := range fuzzFuncs {
		t.Run(f, func(t *testing.T) {
			t.Logf("Running fuzz test %v for %v", f, fuzzTime)
			err := runFuzz(f, fuzzTime)
			if err != nil {
				t.Error("fuzz", f, err)
			}
		})
	}
}
