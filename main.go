package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
)

const defaultTimeout = 15 * time.Second

//go:generate go run gen/gen_services.go

type Service struct {
	Hostname string `json:"hostname"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Text     string `json:"text"` // Joined TXT records
}

func discover(name string, output_filter []string) ([]Service, error) {
	// debug now controlled via env MDNS_DEBUG
	debug := false
	if os.Getenv("MDNS_DEBUG") == "1" || strings.ToLower(os.Getenv("MDNS_DEBUG")) == "true" {
		debug = true
	}
	nresults := 0
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil, fmt.Errorf("init resolver: %w", err)
	}

	if len(output_filter) == 0 {
		output_filter = append(output_filter, "count", "hostname", "address", "port", "text")
	}

	selectedFields := make(map[string]struct{}, len(output_filter))
	for _, f := range output_filter {
		f = strings.TrimSpace(f)
		if f != "" {
			selectedFields[f] = struct{}{}
		}
	}

	if debug {
		fmt.Printf("Showing: ")
		for _, f := range output_filter {
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
			return collected, nil
		case entry, ok := <-entries:
			if !ok {
				return collected, nil
			}

			emit := func(host string, addrStr string, port int, joinedTXT string) {
				key := host + "|" + addrStr + "|" + fmt.Sprint(port)
				if _, exists := seen[key]; exists {
					return
				}
				seen[key] = struct{}{}
				nresults++
				if _, ok := selectedFields["count"]; ok {
					fmt.Printf("%d ", nresults)
				}
				if _, ok := selectedFields["hostname"]; ok {
					fmt.Printf("%s ", host)
				}
				if _, ok := selectedFields["address"]; ok {
					fmt.Printf("%s ", addrStr)
				}
				if _, ok := selectedFields["port"]; ok {
					fmt.Printf("%d ", port)
				}
				if _, ok := selectedFields["text"]; ok && joinedTXT != "" {
					fmt.Printf("%s ", joinedTXT)
				}
				fmt.Println()
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
}

func main() {
	progname := os.Args[0]
	version := "1"
	service_filter := os.Getenv("MDNS_SERVICE_FILTER")
	field_filter := os.Getenv("MDNS_FIELD_FILTER")
	var output_filter []string

	if len(os.Args) > 1 {
		if "help" == os.Args[1] {
			help(progname, version)
			os.Exit(0)
		} else if "show-fields" == os.Args[1] {
			if len(os.Args) == 2 {
				fmt.Printf("Missing output filter. Please specify what to output with \"show-fields\"\n")
				help(progname, version)
				os.Exit(1)
			}
			for _, v := range strings.Split(os.Args[2], ",") {
				output_filter = append(output_filter, strings.TrimSpace(v))
			}
		}
	}

	// Apply env var field filter only if not already set by CLI
	if len(output_filter) == 0 && field_filter != "" {
		for _, v := range strings.Split(field_filter, ",") {
			output_filter = append(output_filter, strings.TrimSpace(v))
		}
	}

	var discovered []Service
	if "" != service_filter {
		res, err := discover(service_filter, output_filter)
		if err != nil {
			log.Fatalln(err)
		}
		discovered = append(discovered, res...)
		return
	}
	for _, s := range services {
		res, err := discover(s, output_filter)
		if err != nil {
			log.Printf("error discovering %s: %v", s, err)
			continue
		}
		discovered = append(discovered, res...)
	}
}
