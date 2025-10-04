package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

const defaultTimeout = 15 * time.Second
const (
	exitOK    = 0
	exitErr   = 1
	exitUsage = 2
)

// OutputMode represents how results should be emitted
type OutputMode int

const (
	OutputText OutputMode = iota
	OutputJSON
)

//go:generate go run gen/gen_services.go

type Service struct {
	Hostname string `json:"hostname"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Text     string `json:"text"`
}

func buildKey(host, addr string, port int) string {
	return host + "|" + addr + "|" + fmt.Sprint(port)
}

func discover(name string, outputFields []string, printResults bool) ([]Service, error) {
	debug := false
	if os.Getenv("MDNS_DEBUG") == "1" || strings.ToLower(os.Getenv("MDNS_DEBUG")) == "true" {
		debug = true
	}
	nresults := 0
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil, fmt.Errorf("init resolver: %w", err)
	}

	if len(outputFields) == 0 {
		outputFields = append(outputFields, "count", "hostname", "address", "port", "text")
	}

	selectedFields := make(map[string]struct{}, len(outputFields))
	for _, f := range outputFields {
		f = strings.TrimSpace(f)
		if f != "" {
			selectedFields[f] = struct{}{}
		}
	}

	if debug && printResults {
		fmt.Printf("Showing: ")
		for _, f := range outputFields {
			fmt.Printf("%s ", f)
		}
		fmt.Println()
	}

	entries := make(chan *zeroconf.ServiceEntry)
	// Allow overriding timeout via MDNS_TIMEOUT (e.g. 30s, 2m), default to defaultTimeout
	timeout := defaultTimeout
	if tv := os.Getenv("MDNS_TIMEOUT"); tv != "" {
		if d, err := time.ParseDuration(tv); err == nil {
			timeout = d
		} else {
			fmt.Fprintf(os.Stderr, "warning: invalid MDNS_TIMEOUT '%s' (using default %s)\n", tv, timeout)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err = resolver.Browse(ctx, name, "local.", entries); err != nil {
		return nil, fmt.Errorf("browse: %w", err)
	}

	var collected []Service
	seen := make(map[string]struct{}) // deduplicate host|addr|port
	for {
		select {
		case <-ctx.Done():
			if debug {
				if ctx.Err() == context.DeadlineExceeded {
					fmt.Fprintf(os.Stderr, "debug: discovery for %s timed out after %s (%d results)\n", name, timeout, len(collected))
				} else {
					fmt.Fprintf(os.Stderr, "debug: discovery for %s context done (%d results)\n", name, len(collected))
				}
			}
			return collected, nil
		case entry, ok := <-entries:
			if !ok {
				if debug {
					fmt.Fprintf(os.Stderr, "debug: discovery channel closed for %s (%d results)\n", name, len(collected))
				}
				return collected, nil
			}

			emit := func(host string, addrStr string, port int, joinedTXT string) {
				key := buildKey(host, addrStr, port)
				if _, exists := seen[key]; exists {
					return
				}
				seen[key] = struct{}{}
				nresults++
				var parts []string
				if _, ok := selectedFields["count"]; ok {
					parts = append(parts, fmt.Sprintf("%d", nresults))
				}
				if _, ok := selectedFields["hostname"]; ok {
					parts = append(parts, host)
				}
				if _, ok := selectedFields["address"]; ok {
					parts = append(parts, addrStr)
				}
				if _, ok := selectedFields["port"]; ok {
					parts = append(parts, fmt.Sprintf("%d", port))
				}
				if _, ok := selectedFields["text"]; ok && joinedTXT != "" {
					parts = append(parts, joinedTXT)
				}
				if printResults {
					fmt.Println(strings.Join(parts, " "))
				}
				collected = append(collected, Service{Hostname: host, Address: addrStr, Port: port, Text: joinedTXT})
			}

			joinedTXT := ""
			if len(entry.Text) > 0 {
				joinedTXT = strings.Join(entry.Text, ";")
			}

			// IPv4
			for _, addr := range entry.AddrIPv4 {
				emit(entry.HostName, addr.String(), entry.Port, joinedTXT)
			}
			// IPv6
			for _, addr := range entry.AddrIPv6 {
				emit(entry.HostName, addr.String(), entry.Port, joinedTXT)
			}
		}
	}
}

func help(name string, version string) {
	fmt.Printf("\n%s version: %s\n\n", name, version)
	fmt.Printf(" Usage:\n\n")
	fmt.Printf("  mdns-discover                             - Show all discovered devices\n\n")
	fmt.Printf("  mdns-discover help                        - Show usage\n\n")
	fmt.Printf("  mdns-discover --output=json               - Output all discovered devices as JSON array\n\n")
	fmt.Printf("  MDNS_SERVICE_FILTER=\"_workstation._tcp\" \\\n")
	fmt.Printf("  mdns-discover                             - Show filtered devices\n\n")
	fmt.Printf("  mdns-discover show-fields \"hostname, address\"    - Show specified attributes for all discovered devices\n\n")
	fmt.Printf("  MDNS_SERVICE_FILTER=\"_workstation._tcp\" \\\n")
	fmt.Printf("  mdns-discover show-fields \"hostname, address\"    - Show specified attributes for filtered devices\n\n")
	fmt.Printf("  Environment variables:\n")
	fmt.Printf("    MDNS_SERVICE_FILTER   - Restrict to a single service type\n")
	fmt.Printf("    MDNS_FIELD_FILTER     - Comma list of fields (count, hostname, address, port, text)\n")
	fmt.Printf("    MDNS_TIMEOUT          - Duration (e.g. 10s, 30s, 1m)\n")
	fmt.Printf("    MDNS_DEBUG            - Set to 1 / true for verbose discovery debug\n\n")
	fmt.Printf("  Flags:\n")
	fmt.Printf("    --output=text|json    - Select output format (default text)\n\n")
}

func main() {
	progname := os.Args[0]
	version := "1"
	serviceFilter := os.Getenv("MDNS_SERVICE_FILTER")
	fieldFilter := os.Getenv("MDNS_FIELD_FILTER")
	var outputFields []string
	outputMode := OutputText
	printResults := true

	// Minimal flag scan for --output[=]<mode>
	filteredArgs := []string{os.Args[0]}
	for i := 1; i < len(os.Args); i++ {
		a := os.Args[i]
		if strings.HasPrefix(a, "--output") {
			mode := ""
			if a == "--output" {
				if i+1 < len(os.Args) {
					mode = os.Args[i+1]
					i++ // consume next
				} else {
					fmt.Fprintf(os.Stderr, "--output flag requires a value (text or json)\n")
					os.Exit(exitUsage)
				}
			} else if strings.HasPrefix(a, "--output=") {
				mode = strings.TrimPrefix(a, "--output=")
			} else { // partial match like --output: treat as error
				fmt.Fprintf(os.Stderr, "Unrecognized flag form: %s\n", a)
				os.Exit(exitUsage)
			}
			mode = strings.ToLower(strings.TrimSpace(mode))
			switch mode {
			case "text", "":
				outputMode = OutputText
			case "json":
				outputMode = OutputJSON
				printResults = false
			default:
				fmt.Fprintf(os.Stderr, "Unknown output mode: %s (expected text or json)\n", mode)
				help(progname, version)
				os.Exit(exitUsage)
			}
			continue
		}
		filteredArgs = append(filteredArgs, a)
	}
	os.Args = filteredArgs

	if len(os.Args) > 1 {
		if "help" == os.Args[1] {
			help(progname, version)
			os.Exit(exitOK)
		} else if "show-fields" == os.Args[1] {
			if len(os.Args) == 2 {
				fmt.Fprintf(os.Stderr, "Missing output filter. Please specify what to output with \"show-fields\"\n")
				help(progname, version)
				os.Exit(exitUsage)
			}
			for _, v := range strings.Split(os.Args[2], ",") {
				outputFields = append(outputFields, strings.TrimSpace(v))
			}
			if len(os.Args) > 3 { // unexpected extra args after show-fields spec
				fmt.Fprintf(os.Stderr, "Unexpected extra arguments: %v\n", os.Args[3:])
				help(progname, version)
				os.Exit(exitUsage)
			}
		} else { // unknown subcommand
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
			help(progname, version)
			os.Exit(exitUsage)
		}
	}

	// Apply env var field filter only if not already set by CLI
	if len(outputFields) == 0 && fieldFilter != "" {
		for _, v := range strings.Split(fieldFilter, ",") {
			outputFields = append(outputFields, strings.TrimSpace(v))
		}
	}

	var discovered []Service
	if "" != serviceFilter {
		res, err := discover(serviceFilter, outputFields, printResults)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: discover %s: %v\n", serviceFilter, err)
			os.Exit(exitErr)
		}
		discovered = append(discovered, res...)
	} else {
		type batch struct {
			services []Service
			err      error
			name     string
		}
		ch := make(chan batch, len(services))
		wg := sync.WaitGroup{}
		for _, s := range services {
			svc := s
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := discover(svc, outputFields, false)
				ch <- batch{services: res, err: err, name: svc}
			}()
		}
		go func() { wg.Wait(); close(ch) }()

		seen := make(map[string]struct{})
		count := 0
		selectedFields := make(map[string]struct{})

		if len(outputFields) == 0 {
			outputFields = append(outputFields, "count", "hostname", "address", "port", "text")
		}

		for _, f := range outputFields {
			f = strings.TrimSpace(f)
			if f != "" {
				selectedFields[f] = struct{}{}
			}
		}
		for b := range ch {
			if b.err != nil {
				fmt.Fprintf(os.Stderr, "warn: discover %s: %v\n", b.name, b.err)
				continue
			}
			for _, srv := range b.services {
				key := buildKey(srv.Hostname, srv.Address, srv.Port)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				count++
				if printResults && outputMode == OutputText {
					parts := []string{}
					if _, ok := selectedFields["count"]; ok {
						parts = append(parts, fmt.Sprintf("%d", count))
					}
					if _, ok := selectedFields["hostname"]; ok {
						parts = append(parts, srv.Hostname)
					}
					if _, ok := selectedFields["address"]; ok {
						parts = append(parts, srv.Address)
					}
					if _, ok := selectedFields["port"]; ok {
						parts = append(parts, fmt.Sprintf("%d", srv.Port))
					}
					if _, ok := selectedFields["text"]; ok && srv.Text != "" {
						parts = append(parts, srv.Text)
					}
					fmt.Println(strings.Join(parts, " "))
				}
				discovered = append(discovered, srv)
			}
		}
	}

	if outputMode == OutputJSON {
		data, err := json.MarshalIndent(discovered, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: marshal json: %v\n", err)
			os.Exit(exitErr)
		}
		fmt.Println(string(data))
		return
	} else if len(discovered) == 0 {
		fmt.Fprintln(os.Stderr, "No services discovered (consider adjusting MDNS_TIMEOUT or filters)")
	}
}
