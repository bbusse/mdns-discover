package main

import (
	"context"
    "fmt"
	"log"
	"os"
	"time"

	"github.com/grandcat/zeroconf"
)

//go:generate go run gen/gen_services.go

func discover(name string) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		log.Fatalln("Failed to initialize resolver:", err.Error())
	}

	entries := make(chan *zeroconf.ServiceEntry)
	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {
		    for n,addr := range entry.AddrIPv4 {
			    fmt.Printf("%d %s", n, entry.HostName)
			    fmt.Printf(" %s", addr)
			    fmt.Printf(" %d", entry.Port)
			    fmt.Printf(" %s", entry.Text)
                fmt.Println()
            }
		}
	}(entries)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	err = resolver.Browse(ctx, name, "local.", entries)
	if err != nil {
		log.Fatalln("Failed to browse:", err.Error())
	}

	<-ctx.Done()
}

func help(name string, version string) {
    fmt.Printf("\n%s version: %s\n\n", name, version)
    fmt.Printf(" Usage:\n\n")
    fmt.Printf("  mdns-discover                             - Show all discovered devices\n\n")
    fmt.Printf("  MDNS_SERVICE_FILTER=\"_workstation._tcp\" \\\n")
    fmt.Printf("  mdns-discover                             - Show filtered devices\n\n")
}

func main() {
    progname := os.Args[0]
    version := "1"
	filter := os.Getenv("MDNS_SERVICE_FILTER")

    if  len(os.Args) > 1 && "help" == os.Args[1] {
        help(progname, version)
    }

    if "" != filter {
	    discover(filter)
    }

    for _, filter := range services {
	    discover(filter)
    }
}
