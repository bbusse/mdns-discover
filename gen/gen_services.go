package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// Include files from data directory
func main() {
	data_path := "data"
	file_suffix := ".txt"
	fs, err := os.ReadDir(data_path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read dir %s: %v\n", data_path, err)
		os.Exit(1)
	}
	out, err := os.Create("services.go")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot create services.go: %v\n", err)
		os.Exit(1)
	}
	if _, err := out.Write([]byte("package main \n\nvar services = [...]string{\n")); err != nil {
		fmt.Fprintf(os.Stderr, "error: write header: %v\n", err)
		os.Exit(1)
	}

	for _, f := range fs {
		if file_suffix != "" && !strings.HasSuffix(f.Name(), file_suffix) {
			continue
		}

		lines, err := readLines(data_path + "/" + f.Name())
		if err != nil {
			fmt.Printf("Failed to read file: %s", err)
		}

		for _, line := range lines {
			if _, err := out.Write([]byte("    \x22" + line + "\x22,\n")); err != nil {
				fmt.Fprintf(os.Stderr, "error: write line %s: %v\n", line, err)
				os.Exit(1)
			}
		}
	}
	if _, err := out.Write([]byte("}\n")); err != nil {
		fmt.Fprintf(os.Stderr, "error: write footer: %v\n", err)
		os.Exit(1)
	}
}
