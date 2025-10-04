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

//go:generate go run gen/gen_services.go

type Service struct {
	Hostname string `json:"hostname"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Text     string `json:"text"`
}

func discover(services []Service, name string, output_filter []string) {
	debug := false
	nresults := 0
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		log.Fatalln("Failed to initialize resolver:", err.Error())
	}

	// Set default output fields if no output_filter given
	if len(output_filter) == 0 {
		output_filter = append(output_filter, "count", "hostname", "address", "port", "text")
	}

	if debug {
		fmt.Printf("Showing: ")
		for _, f := range output_filter {
			fmt.Printf("%s ", f)
		}
		fmt.Println()
	}

	entries := make(chan *zeroconf.ServiceEntry)
	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {
			for _, addr := range entry.AddrIPv4 {
				nresults++
				if contains(output_filter, "count") {
					fmt.Printf("%d ", nresults)
				}
				if contains(output_filter, "hostname") {
					fmt.Printf("%s ", entry.HostName)
				}
				if contains(output_filter, "address") {
					fmt.Printf("%s ", addr)
				}
				if contains(output_filter, "port") {
					fmt.Printf("%d ", entry.Port)
				}
				if contains(output_filter, "text") && (len(entry.Text) > 0) {
					fmt.Printf("%s ", entry.Text)
				}
				fmt.Println()
				service_data := Service{Hostname: entry.HostName,
					Address: fmt.Sprintf("%s", addr),
					Port:    entry.Port,
					Text:    fmt.Sprintf("%s", entry.Text)}
				services = append(services, service_data)
			}
		}
	}(entries)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	err = resolver.Browse(ctx, name, "local.", entries)
	if err != nil {
		log.Fatalln("Failed to browse:", err.Error())
	}

	fmt.Printf("%v", entries)

	<-ctx.Done()
}

func contains(list []string, element string) bool {
	for _, v := range list {
		if v == element {
			return true
		}
	}
	return false
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
}

func main() {
	progname := os.Args[0]
	version := "1"
	service_filter := os.Getenv("MDNS_SERVICE_FILTER")
	field_filter := os.Getenv("MDNS_FIELD_FILTER")
	var output_filter []string

	if len(os.Args) > 1 {
		// Show help
		if "help" == os.Args[1] {
			help(progname, version)
			os.Exit(0)
		} else if "show-fields" == os.Args[1] {
			if len(os.Args) == 2 {
				fmt.Printf("Missing output filter. Please specify what to output with \"show\"\n")
				help(progname, version)
				os.Exit(1)
			} else {
				var output_filter_toks []string
				output_filter_toks = strings.Split(os.Args[2], ",")
				for _, v := range output_filter_toks {
					output_filter = append(output_filter, strings.TrimSpace(v))
				}
			}
			// Check if env var is set, argument takes precedence
		} else if field_filter != "" {
			var output_filter_toks []string
			output_filter_toks = strings.Split(field_filter, ",")
			for _, v := range output_filter_toks {
				output_filter = append(output_filter, strings.TrimSpace(v))
			}
		}
	}

	var discovered_services []Service

	if "" != service_filter {
		discover(discovered_services, service_filter, output_filter)
		os.Exit(0)
	}

	for _, service_filter := range services {
		discover(discovered_services, service_filter, output_filter)
	}
}
