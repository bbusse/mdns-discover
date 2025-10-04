// SPDX-License-Identifier: BSD-3-Clause
//
// mdns-discover
//
// Copyright (c) 2023-2025 Björn Busse
// Author: Björn Busse
// Contributors:
//
// This source code is licensed under the BSD 3-Clause License found in the
// LICENSE file in the root directory of this source tree.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"

	"github.com/bbusse/mdns-discover/internal/docmeta"
)

const defaultTimeout = 15 * time.Second
const (
	exitOK          = 0
	exitErr         = 1
	exitUsage       = 2
	exitResolveInit = 3
	exitBrowseFail  = 4
	exitTimeoutZero = 5
)

// Sentinel errors for classification
var (
	errResolverInit         = fmt.Errorf("resolver init failed")
	errBrowseFailed         = fmt.Errorf("browse failed")
	errTimedOutZero         = fmt.Errorf("timeout no results")
	errNoServicesConfigured = fmt.Errorf("no built-in services configured")
)

// Maximum number of simultaneous discover operations (overridable)
var maxConcurrentDiscover = 10

func exit(code int) {
	os.Exit(code)
}

// OutputMode represents how results should be emitted
type OutputMode int

const (
	OutputText OutputMode = iota
	OutputJSON
)

//go:generate go run gen/gen_services.go

// DiscoveryStats holds aggregate information about the multi-service discovery run
type DiscoveryStats struct {
	SuppressedTimeouts int
	Errors             int
	Attempts           int
	ServiceTypeCounts  map[string]int
	Warnings           []string
}

func discover(name string, outputFields []string, printResults bool, timeout time.Duration, debug bool) ([]Service, error) {
	nresults := 0
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errResolverInit, err)
	}

	outputFields, selectedFields := normalizeOutputFields(outputFields)

	if debug && printResults {
		fmt.Printf("Showing: ")
		for _, f := range outputFields {
			fmt.Printf("%s ", f)
		}
		fmt.Println()
	}

	entries := make(chan *zeroconf.ServiceEntry)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err = resolver.Browse(ctx, name, "local.", entries); err != nil {
		return nil, fmt.Errorf("%w: %v", errBrowseFailed, err)
	}

	var collected []Service
	// Deduplicate host|addr|port
	seen := make(map[string]struct{})
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
			if ctx.Err() == context.DeadlineExceeded && len(collected) == 0 {
				return collected, errTimedOutZero
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
				line := buildOutputLine(selectedFields, nresults, name, host, addrStr, port, joinedTXT)
				if printResults {
					fmt.Println(line)
				}
				collected = append(collected, Service{ServiceType: name, Hostname: host, Address: addrStr, Port: port, Text: joinedTXT})
			}

			joinedTXT, txtMap := parseTXT(entry.Text)

			// IPv4
			for _, addr := range entry.AddrIPv4 {
				emit(entry.HostName, addr.String(), entry.Port, joinedTXT)
				if len(txtMap) > 0 {
					collected[len(collected)-1].TxtMap = txtMap
				}
			}
			// IPv6
			for _, addr := range entry.AddrIPv6 {
				emit(entry.HostName, addr.String(), entry.Port, joinedTXT)
				if len(txtMap) > 0 {
					collected[len(collected)-1].TxtMap = txtMap
				}
			}
		}
	}
}

// DiscoverAll concurrently discovers across multiple service names
func discoverAll(serviceNames []string, outputFields []string, printResults bool, outputMode OutputMode, timeout time.Duration, debug bool) ([]Service, DiscoveryStats, error) {
	// Guard empty services list
	if len(serviceNames) == 0 {
		return nil, DiscoveryStats{}, errNoServicesConfigured
	}
	type batch struct {
		services []Service
		err      error
		name     string
	}
	ch := make(chan batch, len(serviceNames))
	wg := sync.WaitGroup{}
	sem := make(chan struct{}, maxConcurrentDiscover)
	for _, s := range serviceNames {
		svc := s
		wg.Add(1)
		go func() {
			sem <- struct{}{}
			defer wg.Done()
			defer func() { <-sem }()
			res, err := discover(svc, outputFields, false, timeout, debug)
			ch <- batch{services: res, err: err, name: svc}
		}()
	}
	go func() { wg.Wait(); close(ch) }()
	seen := make(map[string]struct{})
	count := 0
	var selectedFields map[string]struct{}
	outputFields, selectedFields = normalizeOutputFields(outputFields)
	var discovered []Service
	stats := DiscoveryStats{ServiceTypeCounts: make(map[string]int)}
	stats.Attempts = len(serviceNames)
	for b := range ch {
		if b.err != nil {
			if errors.Is(b.err, errTimedOutZero) && !debug {
				stats.SuppressedTimeouts++
				stats.Warnings = append(stats.Warnings, fmt.Sprintf("discover %s: %v (suppressed)", b.name, b.err))
				continue
			}
			stats.Errors++
			msg := fmt.Sprintf("discover %s: %v", b.name, b.err)
			stats.Warnings = append(stats.Warnings, msg)
			fmt.Fprintf(os.Stderr, "warn: %s\n", msg)
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
				line := buildOutputLine(selectedFields, count, b.name, srv.Hostname, srv.Address, srv.Port, srv.Text)
				fmt.Println(line)
			}
			srv.ServiceType = b.name
			stats.ServiceTypeCounts[b.name]++
			discovered = append(discovered, srv)
		}
	}
	return discovered, stats, nil
}

// PrintSummary outputs a scan summary
func printSummary(discovered []Service, start time.Time, enabled bool, stats DiscoveryStats, color bool) {
	if !enabled {
		return
	}
	elapsed := time.Since(start).Truncate(time.Millisecond)
	// ANSI color codes (only used when color=true)
	reset := ""
	bold := ""
	green := ""
	yellow := ""
	red := ""
	if color {
		reset = "\033[0m"
		bold = "\033[1m"
		green = "\033[32m"
		yellow = "\033[33m"
		red = "\033[31m"
	}
	if len(discovered) == 0 {
		msg := fmt.Sprintf("Summary: Completed in %s — No services found", elapsed)
		if stats.SuppressedTimeouts > 0 {
			msg += fmt.Sprintf(" (%d suppressed timeouts)", stats.SuppressedTimeouts)
		}
		fmt.Fprintf(os.Stderr, "%s%s%s\n", bold, msg, reset)
		return
	}
	unique := make(map[string]struct{})
	for _, d := range discovered {
		if d.ServiceType != "" {
			unique[d.ServiceType] = struct{}{}
		}
	}
	us := len(unique)
	inst := len(discovered)
	elapsedSec := time.Since(start).Seconds()
	rate := 0.0
	if elapsedSec > 0 {
		rate = float64(inst) / elapsedSec
	}
	svcWord := "service types"
	if us == 1 {
		svcWord = "service type"
	}
	instWord := "instances"
	if inst == 1 {
		instWord = "instance"
	}
	usStr := fmt.Sprintf("%d %s", us, svcWord)
	instStr := fmt.Sprintf("%d %s", inst, instWord)
	if color {
		usStr = green + usStr + reset
		instStr = green + instStr + reset
	}
	extras := []string{fmt.Sprintf("%.2f inst/s", rate)}
	if stats.SuppressedTimeouts > 0 {
		st := fmt.Sprintf("%d suppressed timeouts", stats.SuppressedTimeouts)
		if color {
			st = yellow + st + reset
		}
		extras = append(extras, st)
	}
	if stats.Errors > 0 {
		er := fmt.Sprintf("%d errors", stats.Errors)
		if color {
			er = red + er + reset
		}
		extras = append(extras, er)
	}
	extraStr := ""
	if len(extras) > 0 {
		extraStr = " (" + strings.Join(extras, ", ") + ")"
	}
	fmt.Fprintf(os.Stderr, "%sSummary:%s Completed in %s — %s, %s%s\n", bold, reset, elapsed, usStr, instStr, extraStr)

	// Top service types display (sorted by count desc)
	if len(stats.ServiceTypeCounts) > 0 {
		type kv struct {
			k string
			v int
		}
		pairs := make([]kv, 0, len(stats.ServiceTypeCounts))
		for k, v := range stats.ServiceTypeCounts {
			pairs = append(pairs, kv{k, v})
		}
		sort.Slice(pairs, func(i, j int) bool {
			if pairs[i].v == pairs[j].v {
				return pairs[i].k < pairs[j].k
			}
			return pairs[i].v > pairs[j].v
		})
		fmt.Fprintf(os.Stderr, "%sTop services:%s\n", bold, reset)
		for i := 0; i < len(pairs); i++ {
			name := pairs[i].k
			cnt := pairs[i].v
			pct := float64(cnt) / float64(inst) * 100
			line := fmt.Sprintf("  %s: %d (%.1f%%)", name, cnt, pct)
			if color {
				line = green + line + reset
			}
			fmt.Fprintln(os.Stderr, line)
		}
	}
}

func help(name string, version string) {
	// Header
	fmt.Printf("%s v%s - mDNS service discovery utility\n", name, version)
	fmt.Printf("Usage: %s [flags] [subcommand]\n\n", name)

	// Commands (static for now)
	fmt.Println("Commands:")
	fmt.Printf("  help                  Show this help text\n")
	fmt.Printf("  show-fields \"a,b,c\"   Limit output to specified comma-separated fields\n\n")

	// Flags sourced from doc metadata
	fmt.Println("Flags:")
	// make deterministic ordering
	finfos := docmeta.FlagInfos()
	sort.Slice(finfos, func(i, j int) bool { return finfos[i].Name < finfos[j].Name })
	for _, f := range finfos {
		// Compose flag syntax like --name<ValueSyntax> aligning descriptions
		syn := "--" + f.Name + f.ValueSyntax
		envPart := ""
		if f.Env != "" {
			envPart = fmt.Sprintf(" (env: %s)", f.Env)
		}
		defPart := ""
		if f.Default != "" {
			defPart = fmt.Sprintf(" (default: %s)", f.Default)
		}
		fmt.Printf("  %-20s %s%s%s\n", syn, f.Description, defPart, envPart)
	}
	fmt.Println()

	// Environment variables section (excluding ones already tied directly to flags for clarity)
	fmt.Println("Environment:")
	einfos := docmeta.EnvInfos()
	sort.Slice(einfos, func(i, j int) bool { return einfos[i].Name < einfos[j].Name })
	for _, e := range einfos {
		fmt.Printf("  %-22s %s\n", e.Name, e.Description)
	}
	fmt.Println()

	// Fields
	fmt.Println("Fields:")
	allowed := docmeta.AllowedFields()
	sort.Strings(allowed)
	fmt.Printf("  Allowed: %s\n", strings.Join(allowed, ", "))
	fmt.Printf("  Unknown field names are ignored\n\n")

	// Output modes
	fmt.Println("Output modes:")
	fmt.Println("  text  One line per discovered (service + address).")
	fmt.Println("  json  Single JSON array (all results).")
	fmt.Println()

	// Examples
	fmt.Println("Examples:")
	exs := docmeta.Examples()
	for _, ex := range exs {
		if ex.Command == "mdns-discover" {
			ex.Command = name
		}
		// Replace leading canonical command if present
		if strings.HasPrefix(ex.Command, "mdns-discover ") {
			ex.Command = name + " " + strings.TrimPrefix(ex.Command, "mdns-discover ")
		}
		fmt.Printf("  %-45s %s\n", ex.Command, ex.Description)
	}
	fmt.Println()

	// Exit codes
	fmt.Println("Exit codes:")
	xcodes := docmeta.ExitCodes()
	sort.Slice(xcodes, func(i, j int) bool { return xcodes[i].Code < xcodes[j].Code })
	for _, x := range xcodes {
		fmt.Printf("  %-3d %s\n", x.Code, x.Meaning)
	}
	fmt.Println()
}

// generateManPage produces an mdoc (BSD-style) man page as a string using docmeta metadata.
// Sections: NAME, SYNOPSIS, DESCRIPTION, FLAGS, ENVIRONMENT, FIELDS, OUTPUT MODES, EXAMPLES, EXIT STATUS
func generateManPage(name, version string) string {
	var b strings.Builder
	date := time.Now().Format("2006-01-02")
	b.WriteString(".Dd " + date + "\n")
	b.WriteString(".Dt " + strings.ToUpper(name) + " 1\n")
	b.WriteString(".Os mdns-discover\n")
	b.WriteString(".Sh NAME\n")
	// Use hyphen in NAME section; mdoc interprets '-' fine, escape not needed.
	b.WriteString(name + " - mDNS service discovery utility\n")
	b.WriteString(".Sh SYNOPSIS\n")
	b.WriteString(".Nm " + name + "\n")
	b.WriteString(".Op Fl -output Ns =text|json\n")
	b.WriteString(".Op Fl -timeout Ns =30s\n")
	b.WriteString(".Op Fl -concurrency Ar n\n")
	b.WriteString(".Op Fl -debug\n")
	b.WriteString(".Op Fl h | Fl -help | Fl -man\n")
	b.WriteString(".Op Ar subcommand\n")
	b.WriteString(".Sh DESCRIPTION\n")
	b.WriteString(".Nm performs multicast DNS (mDNS / DNS-SD) discovery across a curated list of service types or an optionally restricted single service. Results can be emitted as plain text lines or a JSON array.\n")

	// FLAGS
	b.WriteString(".Sh FLAGS\n")
	finfos := docmeta.FlagInfos()
	sort.Slice(finfos, func(i, j int) bool { return finfos[i].Name < finfos[j].Name })
	for _, f := range finfos {
		syn := "--" + f.Name + f.ValueSyntax
		b.WriteString(".It Fl " + syn + "\n")
		parts := []string{f.Description}
		if f.Default != "" {
			parts = append(parts, "default: "+f.Default)
		}
		if f.Env != "" {
			parts = append(parts, "env: "+f.Env)
		}
		b.WriteString(strings.Join(parts, "; ") + "\n")
	}

	// ENVIRONMENT
	b.WriteString(".Sh ENVIRONMENT\n")
	einfos := docmeta.EnvInfos()
	sort.Slice(einfos, func(i, j int) bool { return einfos[i].Name < einfos[j].Name })
	for _, e := range einfos {
		b.WriteString(".It Ev " + e.Name + "\n" + e.Description + "\n")
	}

	// FIELDS
	b.WriteString(".Sh FIELDS\n")
	allowed := docmeta.AllowedFields()
	sort.Strings(allowed)
	b.WriteString("Allowed output fields: " + strings.Join(allowed, ", ") + ". Unknown names are ignored.\n")

	// OUTPUT MODES
	b.WriteString(".Sh OUTPUT MODES\n")
	b.WriteString("text: One line per discovered service instance (fields space-separated).\n")
	b.WriteString("json: Single JSON array containing all discovered services.\n")

	// EXAMPLES
	b.WriteString(".Sh EXAMPLES\n")
	exs := docmeta.Examples()
	for _, ex := range exs {
		cmd := ex.Command
		if cmd == "mdns-discover" {
			cmd = name
		} else if strings.HasPrefix(cmd, "mdns-discover ") {
			cmd = name + " " + strings.TrimPrefix(cmd, "mdns-discover ")
		}
		b.WriteString(".It \n" + cmd + "\n" + ex.Description + "\n")
	}

	// EXIT STATUS
	b.WriteString(".Sh EXIT STATUS\n")
	xcodes := docmeta.ExitCodes()
	sort.Slice(xcodes, func(i, j int) bool { return xcodes[i].Code < xcodes[j].Code })
	for _, x := range xcodes {
		b.WriteString(fmt.Sprintf(".It %d %s\n", x.Code, x.Meaning))
	}

	b.WriteString(".Sh VERSION\n" + version + "\n")
	b.WriteString(".Sh SOURCE\nProject page: https://github.com/bbusse/mdns-discover\n")
	b.WriteString(".Sh SEE ALSO\nmulticast DNS (mDNS), DNS-SD specifications\n")
	return b.String()
}

func main() {
	progname := os.Args[0]
	version := "1"
	serviceFilter := os.Getenv("MDNS_SERVICE_FILTER")
	fieldFilter := os.Getenv("MDNS_FIELD_FILTER")
	debug := false
	if os.Getenv("MDNS_DEBUG") == "1" || strings.ToLower(os.Getenv("MDNS_DEBUG")) == "true" {
		debug = true
	}
	var outputFields []string
	outputMode := OutputText
	printResults := true

	// Establish defaults (env may override defaults; flags override env)
	defaultConcurrency := maxConcurrentDiscover
	if v := os.Getenv("MDNS_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			defaultConcurrency = n
		}
	}

	var outputModeStr string
	var wantHelp bool
	var wantMan bool
	var debugFlag bool
	var noColorFlag bool
	var summaryFlag bool
	var concurrency int
	var timeoutFlag string
	var effectiveTimeout time.Duration

	fs := flag.NewFlagSet(progname, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		help(progname, version)
	}
	fs.StringVar(&outputModeStr, "output", "text", "Output format: text or json")
	fs.BoolVar(&wantHelp, "h", false, "Show help and exit")
	fs.BoolVar(&wantHelp, "help", false, "Show help and exit")
	fs.BoolVar(&wantMan, "man", false, "Output man page (mdoc) to stdout and exit")
	fs.BoolVar(&debugFlag, "debug", false, "Enable verbose debug output (overrides MDNS_DEBUG env)")
	fs.BoolVar(&summaryFlag, "summary", false, "Print summary (show all service types with counts)")
	fs.BoolVar(&noColorFlag, "no-color", false, "Disable ANSI color in summary output")
	fs.IntVar(&concurrency, "concurrency", defaultConcurrency, "Simultaneous discovery goroutines (env MDNS_CONCURRENCY)")
	fs.StringVar(&timeoutFlag, "timeout", "", "Discovery timeout (e.g. 10s, 30s, 1m) overrides env MDNS_TIMEOUT")

	if err := fs.Parse(os.Args[1:]); err != nil {
		// flag package already prints an error; show concise usage
		fs.Usage()
		exit(exitUsage)
	}

	if wantHelp {
		help(progname, version)
		exit(exitOK)
	}
	if wantMan {
		fmt.Print(generateManPage(progname, version))
		exit(exitOK)
	}

	// Apply debug flag override
	if debugFlag {
		debug = true
	}

	// summaryFlag already indicates enabling; we now always list all service types when enabled

	startTime := time.Now()

	// Apply parsed flag values
	switch strings.ToLower(strings.TrimSpace(outputModeStr)) {
	case "text", "":
		outputMode = OutputText
	case "json":
		outputMode = OutputJSON
		printResults = false
	default:
		fmt.Fprintf(os.Stderr, "Unknown --output value: %s (expected text or json)\n", outputModeStr)
		fs.Usage()
		exit(exitUsage)
	}
	if concurrency > 0 {
		maxConcurrentDiscover = concurrency
	} else {
		fmt.Fprintf(os.Stderr, "Invalid --concurrency value: %d (must be > 0)\n", concurrency)
		fs.Usage()
		exit(exitUsage)
	}

	// If timeout flag provided, set environment override chain by exporting value into local var used later
	// Determine effective timeout (flag > env > default)
	effectiveTimeout = defaultTimeout
	if envTO := os.Getenv("MDNS_TIMEOUT"); envTO != "" {
		if d, err := time.ParseDuration(envTO); err == nil {
			effectiveTimeout = d
		} else {
			fmt.Fprintf(os.Stderr, "warning: invalid MDNS_TIMEOUT '%s' (using default %s)\n", envTO, effectiveTimeout)
		}
	}
	if timeoutFlag != "" {
		if d, err := time.ParseDuration(timeoutFlag); err == nil {
			effectiveTimeout = d
		} else {
			fmt.Fprintf(os.Stderr, "Invalid --timeout value: %s\n", timeoutFlag)
			fs.Usage()
			exit(exitUsage)
		}
	}

	// Remaining args (subcommands)
	args := fs.Args()

	if len(args) > 0 {
		if args[0] == "help" {
			help(progname, version)
			exit(exitOK)
		} else if args[0] == "man" {
			fmt.Print(generateManPage(progname, version))
			exit(exitOK)
		} else if args[0] == "show-fields" {
			if len(args) == 1 {
				fmt.Fprintf(os.Stderr, "Missing output filter. Please specify what to output with \"show-fields\"\n")
				help(progname, version)
				exit(exitUsage)
			}
			for _, v := range strings.Split(args[1], ",") {
				outputFields = append(outputFields, strings.TrimSpace(v))
			}
			if len(args) > 2 {
				fmt.Fprintf(os.Stderr, "Unexpected extra arguments: %v\n", args[2:])
				help(progname, version)
				exit(exitUsage)
			}
		} else {
			// Unknown subcommand
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
			help(progname, version)
			exit(exitUsage)
		}
	}

	// Apply env var field filter only if not already set by CLI
	if len(outputFields) == 0 && fieldFilter != "" {
		for _, v := range strings.Split(fieldFilter, ",") {
			outputFields = append(outputFields, strings.TrimSpace(v))
		}
	}

	var discovered []Service
	stats := DiscoveryStats{}
	if serviceFilter != "" {
		res, err := discover(serviceFilter, outputFields, printResults, effectiveTimeout, debug)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: discover %s: %v\n", serviceFilter, err)
			// Classify exit code
			code := exitErr
			if errors.Is(err, errResolverInit) {
				code = exitResolveInit
			} else if errors.Is(err, errBrowseFailed) {
				code = exitBrowseFail
			} else if errors.Is(err, errTimedOutZero) {
				code = exitTimeoutZero
			}
			exit(code)
		}
		discovered = append(discovered, res...)
	} else {
		res, st, err := discoverAll(services[:], outputFields, printResults, outputMode, effectiveTimeout, debug)
		if err != nil {
			if errors.Is(err, errNoServicesConfigured) {
				fmt.Fprintln(os.Stderr, "No built-in services available (services list empty) — rebuild may be required")
				exit(exitUsage)
			}
			fmt.Fprintf(os.Stderr, "error: multi-discover: %v\n", err)
			exit(exitErr)
		}
		discovered = append(discovered, res...)
		stats = st
	}

	if outputMode == OutputJSON {
		if summaryFlag {
			elapsedDur := time.Since(startTime).Truncate(time.Millisecond)
			unique := make(map[string]struct{})
			for _, d := range discovered {
				if d.ServiceType != "" {
					unique[d.ServiceType] = struct{}{}
				}
			}
			elapsedSec := time.Since(startTime).Seconds()
			rate := 0.0
			if elapsedSec > 0 {
				rate = float64(len(discovered)) / elapsedSec
			}
			payload := struct {
				Results []Service `json:"results"`
				Summary struct {
					Elapsed       string  `json:"elapsed"`
					ServiceTypes  int     `json:"service_types"`
					Instances     int     `json:"instances"`
					InstancesPerS float64 `json:"instances_per_second"`
					SuppressedTO  int     `json:"suppressed_timeouts"`
					Errors        int     `json:"errors"`
				} `json:"summary"`
			}{Results: discovered}
			payload.Summary.Elapsed = elapsedDur.String()
			payload.Summary.ServiceTypes = len(unique)
			payload.Summary.Instances = len(discovered)
			payload.Summary.InstancesPerS = rate
			payload.Summary.SuppressedTO = stats.SuppressedTimeouts
			payload.Summary.Errors = stats.Errors
			data, err := json.MarshalIndent(payload, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: marshal json: %v\n", err)
				exit(exitErr)
			}
			fmt.Println(string(data))
			return
		}
		data, err := json.MarshalIndent(discovered, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: marshal json: %v\n", err)
			exit(exitErr)
		}
		fmt.Println(string(data))
		return
	} else if len(discovered) == 0 {
		fmt.Fprintln(os.Stderr, "No services discovered (consider adjusting MDNS_TIMEOUT or filters)")
		// Color detection for TTY
		color := false
		// Simple TTY check via Stat mode (fallback without x/term)
		if fi, err := os.Stderr.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
			color = true
		}
		printSummary(discovered, startTime, summaryFlag, stats, color && !noColorFlag)
	}
	color := false
	if fi, err := os.Stderr.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
		color = true
	}
	printSummary(discovered, startTime, summaryFlag, stats, color && !noColorFlag)
}
