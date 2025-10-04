// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"fmt"
	"strings"
)

// Service describes a discovered service instance.
type Service struct {
	ServiceType string            `json:"service,omitempty"`
	Hostname    string            `json:"hostname"`
	Address     string            `json:"address"`
	Port        int               `json:"port"`
	Text        string            `json:"text"`
	TxtMap      map[string]string `json:"txtMap,omitempty"`
}

// BuildOutputLine constructs a space separated line for the selected fields in a fixed order
func buildOutputLine(selectedFields map[string]struct{}, seq int, serviceName, host, addr string, port int, txt string) string {
	parts := []string{}
	if _, ok := selectedFields["count"]; ok {
		parts = append(parts, fmt.Sprintf("%d", seq))
	}
	if _, ok := selectedFields["service"]; ok {
		parts = append(parts, serviceName)
	}
	if _, ok := selectedFields["hostname"]; ok {
		parts = append(parts, host)
	}
	if _, ok := selectedFields["address"]; ok {
		parts = append(parts, addr)
	}
	if _, ok := selectedFields["port"]; ok {
		parts = append(parts, fmt.Sprintf("%d", port))
	}
	if _, ok := selectedFields["text"]; ok && txt != "" {
		parts = append(parts, txt)
	}
	return strings.Join(parts, " ")
}

// NormalizeOutputFields applies defaults if none provided and returns the
// Final slice plus a set for membership tests
func normalizeOutputFields(fields []string) ([]string, map[string]struct{}) {
	if len(fields) == 0 {
		fields = append(fields, "count", "service", "hostname", "address", "port", "text")
	}
	selected := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if _, exists := selected[f]; exists {
			continue
		}
		selected[f] = struct{}{}
	}
	ordered := make([]string, 0, len(selected))
	seen := make(map[string]struct{}, len(selected))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if _, ok := seen[f]; ok {
			continue
		}
		if _, ok := selected[f]; ok {
			ordered = append(ordered, f)
			seen[f] = struct{}{}
		}
	}
	return ordered, selected
}

// BuildKey returns a deduplication key
func buildKey(host, addr string, port int) string {
	return host + "|" + addr + "|" + fmt.Sprint(port)
}

// ParseTXT records into joined string and key=value map
func parseTXT(txt []string) (string, map[string]string) {
	if len(txt) == 0 {
		return "", nil
	}
	joined := strings.Join(txt, ";")
	m := make(map[string]string)
	for _, raw := range txt {
		if raw == "" {
			continue
		}
		parts := strings.SplitN(raw, "=", 2)
		if len(parts) == 2 && parts[0] != "" {
			m[parts[0]] = parts[1]
		}
	}
	if len(m) == 0 {
		return joined, nil
	}
	return joined, m
}
