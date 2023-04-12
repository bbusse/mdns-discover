package main

import (
    "bufio"
    "fmt"
    "io/ioutil"
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
    fs, _ := ioutil.ReadDir(data_path)
    out, _ := os.Create("services.go")
    out.Write([]byte("package main \n\nvar services = [...]string{\n"))

    for _, f := range fs {
        if "" != file_suffix {
            if ! strings.HasSuffix(f.Name(), file_suffix) {
                break
            }
        }

        lines, err := readLines(data_path + "/" + f.Name())
        if err != nil {
            fmt.Printf("Failed to read file: %s", err)
        }

        for _, line := range lines {
            out.Write([]byte("    \x22" + line + "\x22,\n"))
        }
    }
    out.Write([]byte("}\n"))
}
