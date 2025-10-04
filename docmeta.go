// SPDX-License-Identifier: BSD-3-Clause
//
// Metadata definitions for documentation generation (help, man page, etc.)
// Incremental introduction: currently not yet wired into help()
// but provides a single source of truth for future generators.
package main

// FlagInfo describes a command-line flag.
type FlagInfo struct {
	Name        string // Flag name without leading dashes
	ValueSyntax string // Syntax hint like "=text|json" or "<n>" or "=30s"
	Default     string // Default value (string form)
	Env         string // Related environment variable (if any)
	Description string // Human description
}

// EnvInfo describes an environment variable.
type EnvInfo struct {
	Name        string
	Description string
}

// Example is a usage example.
type Example struct {
	Command     string
	Description string
}

// ExitCode documents an exit status meaning.
type ExitCode struct {
	Code    int
	Meaning string
}

var flagInfos = []FlagInfo{
	{Name: "output", ValueSyntax: "=text|json", Default: "text", Env: "", Description: "Output format"},
	{Name: "timeout", ValueSyntax: "=30s", Default: "15s", Env: "MDNS_TIMEOUT", Description: "Discovery timeout"},
	{Name: "concurrency", ValueSyntax: "<n>", Default: "10", Env: "MDNS_CONCURRENCY", Description: "Simultaneous lookups"},
}

var envInfos = []EnvInfo{
	{Name: "MDNS_SERVICE_FILTER", Description: "Restrict to a single service type"},
	{Name: "MDNS_FIELD_FILTER", Description: "Comma list of fields (overridden by show-fields)"},
	{Name: "MDNS_TIMEOUT", Description: "Discovery timeout (duration string)"},
	{Name: "MDNS_DEBUG", Description: "Verbose debug output (1 / true)"},
	{Name: "MDNS_CONCURRENCY", Description: "Max concurrent service lookups"},
}

var examples = []Example{
	{Command: "mdns-discover", Description: "Discover using defaults"},
	{Command: "mdns-discover --output=json", Description: "JSON array output"},
	{Command: "MDNS_SERVICE_FILTER=\"_workstation._tcp\" mdns-discover", Description: "Filter to a specific service"},
	{Command: "mdns-discover show-fields \"hostname,address,port\"", Description: "Limit output columns"},
	{Command: "MDNS_TIMEOUT=30s mdns-discover --concurrency=5", Description: "Override timeout and concurrency"},
}

var exitCodes = []ExitCode{
	{Code: 0, Meaning: "Success"},
	{Code: 1, Meaning: "Runtime error"},
	{Code: 2, Meaning: "Usage error"},
}

var allowedFields = []string{"count", "service", "hostname", "address", "port", "text"}
