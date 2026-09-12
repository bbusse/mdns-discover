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
	"syscall"
	"time"

	"net"

	"github.com/bbusse/mdns-discover/internal/docmeta"
)

const defaultTimeout = 15 * time.Second
const version = "1"
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
	errUsage                = fmt.Errorf("usage error")
	errShowHelp             = fmt.Errorf("show help")
	errShowMan              = fmt.Errorf("show man")
	errNetPermission        = fmt.Errorf("network permission denied")
	errNoSuchHost           = fmt.Errorf("no such host")
)

// ClassifyExit returns the exit code for a given error
func classifyExit(err error) int {
	if err == nil {
		return exitOK
	}
	switch {
	case errors.Is(err, errUsage):
		return exitUsage
	case errors.Is(err, errResolverInit):
		return exitResolveInit
	case errors.Is(err, errBrowseFailed):
		return exitBrowseFail
	case errors.Is(err, errTimedOutZero):
		return exitTimeoutZero
	default:
		return exitErr
	}
}

// Default for the deprecated --concurrency flag (kept for compatibility, no effect)
const defaultMaxConcurrency = 10

// Maximum allowed concurrency cap
const maxConcurrencyCap = 256

func discoverExit(code int) {
	os.Exit(code)
}

// failAndExit prints a contextual error message (if err non-nil) and exits using classifyExit.
// Context should be a short phrase (e.g. "discover <service>"). Empty context omits prefix.
func failAndExit(err error, context string) {
	if err == nil {
		discoverExit(exitOK)
	}
	if context != "" {
		fmt.Fprintf(os.Stderr, "error: %s: %v\n", context, err)
	} else {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	}
	discoverExit(classifyExit(err))
}

// usageFail shows usage and exits with the usage code, reporting msg if non-empty
func usageFail(fs *flag.FlagSet, msg string) {
	fs.Usage()
	if msg != "" {
		failAndExit(fmt.Errorf("%w: %s", errUsage, msg), "")
	} else {
		failAndExit(errUsage, "")
	}
}

// OutputMode represents how results should be emitted
type OutputMode int

const (
	OutputText OutputMode = iota
	OutputJSON
)

// Build a set (map) of allowed output field names for quick membership tests.
var (
	allowedFieldOnce sync.Once
	allowedFieldMap  map[string]struct{}
)

func allowedFieldSet() map[string]struct{} {
	allowedFieldOnce.Do(func() {
		m := make(map[string]struct{})
		for _, f := range docmeta.AllowedFields() {
			m[f] = struct{}{}
		}
		allowedFieldMap = m
	})
	return allowedFieldMap
}

// Parse a comma or space separated raw field list string into a slice of trimmed non-empty fields.
func parseFieldList(raw string) []string {
	if raw == "" {
		return nil
	}
	// Allow both comma and whitespace as delimiters
	parts := strings.Fields(strings.ReplaceAll(raw, ",", " "))
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

//go:generate go run gen/gen_services.go

func classifyBrowseError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
		return fmt.Errorf("%w: %v", errNetPermission, err)
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return fmt.Errorf("%w: multicast send rejected (on macOS check the Local Network privacy permission of the launching app): %v", errNetPermission, err)
	default:
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return fmt.Errorf("%w: %v", errNoSuchHost, err)
		}
		return err
	}
}

// runDiscovery browses all serviceTypes over one shared socket pair until the
// timeout expires. Results are appended in arrival order and, when printResults
// is set, printed as they arrive.
func runDiscovery(serviceTypes []string, selectedFields map[string]struct{}, printResults bool, timeout time.Duration, debug bool, ifaceAllow map[int]struct{}) ([]Service, error) {
	browser, err := newMDNSBrowser(ifaceAllow, debug)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errResolverInit, err)
	}
	defer browser.close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var collected []Service
	// Deduplicate service|host|addr|port
	seen := make(map[string]struct{})
	count := 0
	_, wantRaw := selectedFields["raw"]
	emit := func(e *mdnsEntry) {
		joinedTXT, txtMap := parseTXT(e.Text)
		add := func(addr net.IP, family string) {
			addrStr := addr.String()
			key := e.ServiceType + "|" + buildKey(e.HostName, addrStr, e.Port)
			if _, dup := seen[key]; dup {
				return
			}
			seen[key] = struct{}{}
			count++
			svc := Service{ServiceType: e.ServiceType, Hostname: e.HostName, Address: addrStr, Port: e.Port, Text: joinedTXT, Family: family}
			if len(txtMap) > 0 {
				svc.TxtMap = txtMap
			}
			if wantRaw {
				svc.Raw = &RawEntry{Instance: e.Instance, Domain: e.Domain, IfIndex: e.IfIndex, TTL: e.TTL, Texts: e.Text}
			}
			if printResults {
				fmt.Println(buildOutputLine(selectedFields, count, svc.ServiceType, svc.Hostname, svc.Address, svc.Port, svc.Text, svc.Family))
			}
			collected = append(collected, svc)
		}
		for _, a := range e.AddrIPv4 {
			add(a, "ipv4")
		}
		for _, a := range e.AddrIPv6 {
			add(a, "ipv6")
		}
	}

	if err := browser.browse(ctx, serviceTypes, "local", ifaceAllow, emit); err != nil {
		return collected, err
	}
	if debug {
		fmt.Fprintf(os.Stderr, "debug: discovery finished after %s (%d service types, %d results)\n", timeout, len(serviceTypes), len(collected))
	}
	return collected, nil
}

// discover browses a single service type. Zero results within the timeout is
// reported as errTimedOutZero.
func discover(name string, outputFields []string, selectedFields map[string]struct{}, printResults bool, timeout time.Duration, debug bool, ifaceAllow map[int]struct{}) ([]Service, error) {
	if debug && printResults {
		fmt.Printf("Showing: %s\n", strings.Join(outputFields, " "))
	}
	res, err := runDiscovery([]string{name}, selectedFields, printResults, timeout, debug, ifaceAllow)
	if err != nil {
		return res, err
	}
	if len(res) == 0 {
		return res, errTimedOutZero
	}
	return res, nil
}

// discoverAll browses every given service type in a single pass over one
// socket pair. Zero results is not an error here.
func discoverAll(serviceNames []string, outputFields []string, selectedFields map[string]struct{}, printResults bool, outputMode OutputMode, timeout time.Duration, debug bool, ifaceAllow map[int]struct{}) ([]Service, error) {
	if len(serviceNames) == 0 {
		return nil, errNoServicesConfigured
	}
	if debug && printResults {
		fmt.Printf("Showing: %s\n", strings.Join(outputFields, " "))
	}
	return runDiscovery(serviceNames, selectedFields, printResults && outputMode == OutputText, timeout, debug, ifaceAllow)
}

// PrintSummary outputs a scan summary
func printSummary(discovered []Service, start time.Time, enabled bool, interfaces []string) {
	if !enabled {
		return
	}
	elapsed := time.Since(start).Truncate(time.Millisecond)
	if len(discovered) == 0 {
		ifaceStr := "all"
		if len(interfaces) > 0 {
			ifaceStr = strings.Join(interfaces, ",")
		}
		fmt.Fprintf(os.Stderr, "Summary: elapsed=%s unique_services=0 instances=0 interfaces=%s\n", elapsed, ifaceStr)
		return
	}
	unique := make(map[string]struct{})
	for _, d := range discovered {
		if d.ServiceType != "" {
			unique[d.ServiceType] = struct{}{}
		}
	}
	ifaceStr := "all"
	if len(interfaces) > 0 {
		ifaceStr = strings.Join(interfaces, ",")
	}
	fmt.Fprintf(os.Stderr, "Summary: elapsed=%s unique_services=%d instances=%d interfaces=%s\n", elapsed, len(unique), len(discovered), ifaceStr)
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
	fmt.Printf("  Unknown field names are ignored\n")
	fmt.Printf("  Field notes: family=address family (ipv4|ipv6); raw=embed raw entry meta (JSON only)\n\n")

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
	b.WriteString("Field notes: family=address family (ipv4|ipv6); raw=embed raw entry meta (JSON only)\n")

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

// Config holds runtime configuration derived from flags, env, and arguments
type Config struct {
	ProgramName    string
	Version        string
	ServiceFilter  string
	FieldFilterEnv string
	Debug          bool
	OutputFields   []string
	OutputMode     OutputMode
	PrintResults   bool
	Concurrency    int
	Timeout        time.Duration
	ShowSummary    bool
	Args           []string
	FlagSet        *flag.FlagSet
	InterfaceNames []string
}

// parseConfig parses command line flags and environment variables into Config
func parseConfig(ver string) (Config, error) {
	progname := os.Args[0]
	serviceFilter := os.Getenv("MDNS_SERVICE_FILTER")
	fieldFilter := os.Getenv("MDNS_FIELD_FILTER")
	debug := false
	if os.Getenv("MDNS_DEBUG") == "1" || strings.ToLower(os.Getenv("MDNS_DEBUG")) == "true" {
		debug = true
	}
	outputMode := OutputText
	printResults := true
	defaultConcurrency := defaultMaxConcurrency
	if v := os.Getenv("MDNS_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			defaultConcurrency = n
		}
	}
	var outputModeStr string
	var interfaceFlag string
	var wantHelp bool
	var wantMan bool
	var debugFlag bool
	var summaryFlag bool
	var concurrency int
	var timeoutFlag string
	var effectiveTimeout time.Duration
	var outputFields []string

	fs := flag.NewFlagSet(progname, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { help(progname, ver) }
	fs.StringVar(&outputModeStr, "output", "text", "Output format: text or json")
	fs.BoolVar(&wantHelp, "h", false, "Show help and exit")
	fs.BoolVar(&wantHelp, "help", false, "Show help and exit")
	fs.BoolVar(&wantMan, "man", false, "Output man page (mdoc) to stdout and exit")
	fs.BoolVar(&debugFlag, "debug", false, "Enable verbose debug output (overrides MDNS_DEBUG env")
	fs.BoolVar(&summaryFlag, "summary", false, "Print summary (elapsed, unique services, instances)")
	fs.IntVar(&concurrency, "concurrency", defaultConcurrency, "Deprecated: accepted for compatibility, discovery now uses a single socket (env MDNS_CONCURRENCY)")
	fs.StringVar(&timeoutFlag, "timeout", "", "Discovery timeout (e.g. 10s, 30s, 1m) overrides env MDNS_TIMEOUT")
	fs.StringVar(&interfaceFlag, "interface", "", "Limit discovery to one or more network interfaces (comma separated)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return Config{}, fmt.Errorf("%w: %v", errUsage, err)
	}
	if wantHelp {
		return Config{}, errShowHelp
	}
	if wantMan {
		return Config{}, errShowMan
	}
	if debugFlag {
		debug = true
	}
	switch strings.ToLower(strings.TrimSpace(outputModeStr)) {
	case "text", "":
		outputMode = OutputText
	case "json":
		outputMode = OutputJSON
		printResults = false
	default:
		return Config{FlagSet: fs}, fmt.Errorf("%w: unknown --output value: %s", errUsage, outputModeStr)
	}
	if concurrency <= 0 {
		return Config{FlagSet: fs}, fmt.Errorf("%w: invalid --concurrency value: %d", errUsage, concurrency)
	}
	if concurrency > maxConcurrencyCap {
		fmt.Fprintf(os.Stderr, "warning: concurrency %d > cap %d (clamping)\n", concurrency, maxConcurrencyCap)
		concurrency = maxConcurrencyCap
	}
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
			return Config{FlagSet: fs}, fmt.Errorf("%w: invalid --timeout value: %s", errUsage, timeoutFlag)
		}
	}
	args := fs.Args()
	// Interface names from env if flag empty
	if interfaceFlag == "" {
		if envIf := os.Getenv("MDNS_INTERFACE"); envIf != "" {
			interfaceFlag = envIf
		}
	}
	var interfaceNames []string
	if interfaceFlag != "" {
		parts := strings.Split(interfaceFlag, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			interfaceNames = append(interfaceNames, p)
		}
		if len(interfaceNames) == 0 {
			return Config{FlagSet: fs}, fmt.Errorf("%w: invalid --interface value (empty after parsing)", errUsage)
		}
	}
	if len(args) > 0 {
		if args[0] == "help" {
			return Config{}, errShowHelp
		} else if args[0] == "man" {
			return Config{}, errShowMan
		} else if args[0] == "show-fields" {
			if len(args) == 1 {
				return Config{FlagSet: fs}, fmt.Errorf("%w: missing output filter for show-fields", errUsage)
			}
			outputFields = parseFieldList(args[1])
			if len(args) > 2 {
				return Config{FlagSet: fs}, fmt.Errorf("%w: unexpected extra arguments: %v", errUsage, args[2:])
			}
		} else {
			return Config{FlagSet: fs}, fmt.Errorf("%w: unknown command: %s", errUsage, args[0])
		}
	}
	if len(outputFields) == 0 && fieldFilter != "" {
		outputFields = parseFieldList(fieldFilter)
	}
	if len(outputFields) > 0 {
		allowed := allowedFieldSet()
		var unknown []string
		seenRequested := make(map[string]struct{})
		var dedupOrdered []string
		for _, f := range outputFields {
			if _, dup := seenRequested[f]; dup {
				continue
			}
			seenRequested[f] = struct{}{}
			if _, ok := allowed[f]; !ok {
				unknown = append(unknown, f)
			}
			if _, ok := allowed[f]; ok {
				dedupOrdered = append(dedupOrdered, f)
			}
		}
		if len(unknown) > 0 {
			return Config{FlagSet: fs}, fmt.Errorf("%w: unknown output field(s): %s", errUsage, strings.Join(unknown, ","))
		}
		outputFields = dedupOrdered
	}
	c := Config{
		ProgramName:    progname,
		Version:        ver,
		ServiceFilter:  serviceFilter,
		FieldFilterEnv: fieldFilter,
		Debug:          debug,
		OutputFields:   outputFields,
		OutputMode:     outputMode,
		PrintResults:   printResults,
		Concurrency:    concurrency,
		Timeout:        effectiveTimeout,
		ShowSummary:    summaryFlag,
		Args:           args,
		FlagSet:        fs,
		InterfaceNames: interfaceNames,
	}
	return c, nil
}

func main() {
	cfg, err := parseConfig(version)
	if err != nil {
		switch {
		case errors.Is(err, errShowHelp):
			help(os.Args[0], version)
			discoverExit(exitOK)
		case errors.Is(err, errShowMan):
			fmt.Print(generateManPage(os.Args[0], version))
			discoverExit(exitOK)
		case errors.Is(err, errUsage):
			if cfg.FlagSet != nil {
				cfg.FlagSet.Usage()
			}
			failAndExit(err, "")
		default:
			failAndExit(err, "parse config")
		}
	}
	startTime := time.Now()
	outputFields, selectedFields := normalizeOutputFields(cfg.OutputFields)
	ifaceAllow := make(map[int]struct{})
	if len(cfg.InterfaceNames) > 0 {
		ifs, _ := net.Interfaces()
		for _, want := range cfg.InterfaceNames {
			for _, ni := range ifs {
				if ni.Name == want {
					ifaceAllow[ni.Index] = struct{}{}
					break
				}
			}
		}
		if len(ifaceAllow) == 0 {
			fmt.Fprintf(os.Stderr, "warning: no matching interfaces for --interface selection (names: %s)\n", strings.Join(cfg.InterfaceNames, ","))
		}
	}
	var discovered []Service
	if cfg.ServiceFilter != "" {
		res, err := discover(cfg.ServiceFilter, outputFields, selectedFields, cfg.PrintResults, cfg.Timeout, cfg.Debug, ifaceAllow)
		if err != nil {
			failAndExit(err, fmt.Sprintf("discover %s", cfg.ServiceFilter))
		}
		discovered = append(discovered, res...)
	} else {
		res, err := discoverAll(services[:], outputFields, selectedFields, cfg.PrintResults, cfg.OutputMode, cfg.Timeout, cfg.Debug, ifaceAllow)
		if err != nil {
			if errors.Is(err, errNoServicesConfigured) {
				if cfg.FlagSet != nil {
					usageFail(cfg.FlagSet, "No built-in services available (services list empty) — rebuild may be required")
				} else {
					usageFail(flag.CommandLine, "No built-in services available (services list empty) — rebuild may be required")
				}
			}
			failAndExit(err, "multi-discover")
		}
		discovered = append(discovered, res...)
	}
	if cfg.OutputMode == OutputJSON {
		data, err := json.MarshalIndent(discovered, "", "  ")
		if err != nil {
			failAndExit(err, "marshal json")
		}
		fmt.Println(string(data))
		if len(discovered) == 0 {
			fmt.Fprintln(os.Stderr, "No services discovered (consider adjusting MDNS_TIMEOUT or filters)")
		}
		printSummary(discovered, startTime, cfg.ShowSummary, cfg.InterfaceNames)
		return
	} else if len(discovered) == 0 {
		fmt.Fprintln(os.Stderr, "No services discovered (consider adjusting MDNS_TIMEOUT or filters)")
	}
	printSummary(discovered, startTime, cfg.ShowSummary, cfg.InterfaceNames)
}
