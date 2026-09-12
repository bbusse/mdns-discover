// SPDX-License-Identifier: BSD-3-Clause
//
// mdns-discover - single-socket mDNS/DNS-SD browser
//
// Copyright (c) 2023-2025 Björn Busse
// Author: Björn Busse
//
// This source code is licensed under the BSD 3-Clause License found in the
// LICENSE file in the root directory of this source tree.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// One pair of UDP sockets (IPv4 + IPv6) is shared by all service types being
// browsed. All PTR questions are packed into a handful of multi-question
// datagrams per query round and every answer is demultiplexed by name in a
// single receive loop. This replaces the previous one-resolver-per-service
// design, which (via grandcat/zeroconf) closed the shared sockets as soon as
// the first browse context expired and split replies between competing readers.

const (
	mdnsPort = 5353
	// Keep query datagrams comfortably below a 1500 byte MTU.
	maxQueryBytes = 1200
	// RFC 6762 §5.2: first retransmission after at least one second, then doubling.
	firstQueryInterval = 1 * time.Second
	maxQueryInterval   = 60 * time.Second
)

var (
	mdnsGroup4 = net.IPv4(224, 0, 0, 251)
	mdnsGroup6 = net.ParseIP("ff02::fb")
	mdnsDst4   = &net.UDPAddr{IP: mdnsGroup4, Port: mdnsPort}
	mdnsDst6   = &net.UDPAddr{IP: mdnsGroup6, Port: mdnsPort}
	// Binding to a multicast address makes Go bind the wildcard with
	// SO_REUSEADDR/SO_REUSEPORT so we can coexist with the system responder.
	mdnsBind4 = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 0), Port: mdnsPort}
	mdnsBind6 = &net.UDPAddr{IP: net.ParseIP("ff02::"), Port: mdnsPort}
)

// mdnsEntry is one discovered (service instance, new address set) as assembled
// from PTR, SRV, TXT and A/AAAA records, possibly spread over several packets.
type mdnsEntry struct {
	ServiceType string // e.g. _ssh._tcp
	Instance    string // instance label without service type and domain
	Domain      string // e.g. local
	HostName    string // SRV target, FQDN with trailing dot
	Port        int
	Text        []string
	TTL         uint32
	IfIndex     int // interface the answer arrived on (0 if unknown)
	AddrIPv4    []net.IP
	AddrIPv6    []net.IP
}

// mdnsPacket is a parsed response plus the interface it arrived on.
type mdnsPacket struct {
	msg     *dns.Msg
	ifIndex int
}

// Sockets

// mdnsBrowser owns the sockets and the list of interfaces they were joined on.
type mdnsBrowser struct {
	conn4   *ipv4.PacketConn
	conn6   *ipv6.PacketConn
	ifaces4 []net.Interface
	ifaces6 []net.Interface
	debug   bool
}

// newMDNSBrowser opens the sockets and joins the mDNS groups on every usable
// interface (or only the allowed ones, when allowed is non-empty).
func newMDNSBrowser(allowed map[int]struct{}, debug bool) (*mdnsBrowser, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	var candidates []net.Interface
	for _, ifi := range all {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 {
			continue
		}
		if len(allowed) > 0 {
			if _, ok := allowed[ifi.Index]; !ok {
				continue
			}
		}
		candidates = append(candidates, ifi)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no up multicast-capable interfaces")
	}

	b := &mdnsBrowser{debug: debug}
	var errs []string

	if c, err := net.ListenUDP("udp4", mdnsBind4); err == nil {
		b.conn4 = ipv4.NewPacketConn(c)
		_ = b.conn4.SetControlMessage(ipv4.FlagInterface, true)
		for i := range candidates {
			if err := b.conn4.JoinGroup(&candidates[i], &net.UDPAddr{IP: mdnsGroup4}); err == nil {
				b.ifaces4 = append(b.ifaces4, candidates[i])
			} else if debug {
				fmt.Fprintf(os.Stderr, "debug: ipv4 join %s: %v\n", candidates[i].Name, err)
			}
		}
		if len(b.ifaces4) == 0 {
			c.Close()
			b.conn4 = nil
			errs = append(errs, "ipv4: no interface joined the mDNS group")
		}
	} else {
		errs = append(errs, "ipv4: "+err.Error())
	}

	if c, err := net.ListenUDP("udp6", mdnsBind6); err == nil {
		b.conn6 = ipv6.NewPacketConn(c)
		_ = b.conn6.SetControlMessage(ipv6.FlagInterface, true)
		for i := range candidates {
			if err := b.conn6.JoinGroup(&candidates[i], &net.UDPAddr{IP: mdnsGroup6}); err == nil {
				b.ifaces6 = append(b.ifaces6, candidates[i])
			} else if debug {
				fmt.Fprintf(os.Stderr, "debug: ipv6 join %s: %v\n", candidates[i].Name, err)
			}
		}
		if len(b.ifaces6) == 0 {
			c.Close()
			b.conn6 = nil
			errs = append(errs, "ipv6: no interface joined the mDNS group")
		}
	} else {
		errs = append(errs, "ipv6: "+err.Error())
	}

	if b.conn4 == nil && b.conn6 == nil {
		return nil, fmt.Errorf("open mDNS sockets: %s", strings.Join(errs, "; "))
	}
	if debug {
		fmt.Fprintf(os.Stderr, "debug: listening ipv4 on %s; ipv6 on %s\n", ifaceNames(b.ifaces4), ifaceNames(b.ifaces6))
	}
	return b, nil
}

func ifaceNames(ifs []net.Interface) string {
	if len(ifs) == 0 {
		return "-"
	}
	names := make([]string, 0, len(ifs))
	for _, ifi := range ifs {
		names = append(names, ifi.Name)
	}
	return strings.Join(names, ",")
}

// close releases the sockets, safe to call more than once. The fields are
// deliberately left set (not nilled) since recvLoop goroutines read them
// concurrently with this call; Close() unblocks their pending ReadFrom
// with an error instead of racing a nil check
func (b *mdnsBrowser) close() {
	if b.conn4 != nil {
		b.conn4.Close()
	}
	if b.conn6 != nil {
		b.conn6.Close()
	}
}

// send writes one packed message to every joined interface of both families.
// It returns the number of successful writes and the last error seen.
func (b *mdnsBrowser) send(buf []byte) (int, error) {
	sent := 0
	var lastErr error
	if b.conn4 != nil {
		for i := range b.ifaces4 {
			cm := ipv4.ControlMessage{IfIndex: b.ifaces4[i].Index}
			if _, err := b.conn4.WriteTo(buf, &cm, mdnsDst4); err != nil {
				lastErr = err
				if b.debug {
					fmt.Fprintf(os.Stderr, "debug: send ipv4 %s: %v\n", b.ifaces4[i].Name, err)
				}
				continue
			}
			sent++
		}
	}
	if b.conn6 != nil {
		for i := range b.ifaces6 {
			cm := ipv6.ControlMessage{IfIndex: b.ifaces6[i].Index}
			if _, err := b.conn6.WriteTo(buf, &cm, mdnsDst6); err != nil {
				lastErr = err
				if b.debug {
					fmt.Fprintf(os.Stderr, "debug: send ipv6 %s: %v\n", b.ifaces6[i].Name, err)
				}
				continue
			}
			sent++
		}
	}
	return sent, lastErr
}

// sendQuestions packs questions into as few datagrams as fit under
// maxQueryBytes and sends each of them.
func (b *mdnsBrowser) sendQuestions(questions []dns.Question) (int, error) {
	sent := 0
	var lastErr error
	for _, buf := range packQuestions(questions) {
		n, err := b.send(buf)
		sent += n
		if err != nil {
			lastErr = err
		}
	}
	return sent, lastErr
}

// packQuestions splits questions into packed query messages no larger than
// maxQueryBytes (a single oversized question still gets its own datagram).
func packQuestions(questions []dns.Question) [][]byte {
	var out [][]byte
	msg := new(dns.Msg)
	flush := func() {
		if len(msg.Question) == 0 {
			return
		}
		if buf, err := msg.Pack(); err == nil {
			out = append(out, buf)
		}
		msg = new(dns.Msg)
	}
	for _, q := range questions {
		msg.Question = append(msg.Question, q)
		if msg.Len() > maxQueryBytes && len(msg.Question) > 1 {
			msg.Question = msg.Question[:len(msg.Question)-1]
			flush()
			msg.Question = append(msg.Question, q)
		}
	}
	flush()
	return out
}

// recvLoop reads datagrams until the socket is closed and forwards parsed
// response messages together with the receiving interface index.
func (b *mdnsBrowser) recvLoop(ctx context.Context, family int, out chan<- mdnsPacket) {
	buf := make([]byte, 65535)
	for {
		var n, ifIndex int
		var err error
		switch family {
		case 4:
			var cm *ipv4.ControlMessage
			n, cm, _, err = b.conn4.ReadFrom(buf)
			if cm != nil {
				ifIndex = cm.IfIndex
			}
		default:
			var cm *ipv6.ControlMessage
			n, cm, _, err = b.conn6.ReadFrom(buf)
			if cm != nil {
				ifIndex = cm.IfIndex
			}
		}
		if err != nil {
			// Closed socket: stop quietly.
			return
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil || !msg.Response {
			continue
		}
		select {
		case out <- mdnsPacket{msg: msg, ifIndex: ifIndex}:
		case <-ctx.Done():
			return
		}
	}
}

// Record demultiplexing (pure, testable)

// instState accumulates the records seen for one service instance.
type instState struct {
	serviceType string
	instance    string
	host        string
	port        int
	txt         []string
	ttl         uint32
	ifIndex     int
	hasSRV      bool
	hasTXT      bool
	sentAddrs   map[string]struct{}
}

// browseState holds everything learned so far for a set of service types.
type browseState struct {
	domain    string
	wanted    map[string]string     // PTR owner name ("_ssh._tcp.local.") -> service type
	questions []dns.Question        // PTR questions, one per service type
	instances map[string]*instState // key: instance FQDN
	hosts     map[string][]net.IP   // key: host FQDN
	allowed   map[int]struct{}      // interface index filter (empty = all)
	emit      func(*mdnsEntry)
}

func newBrowseState(serviceTypes []string, domain string, allowed map[int]struct{}, emit func(*mdnsEntry)) *browseState {
	domain = strings.Trim(domain, ".")
	if domain == "" {
		domain = "local"
	}
	s := &browseState{
		domain:    domain,
		wanted:    make(map[string]string, len(serviceTypes)),
		instances: make(map[string]*instState),
		hosts:     make(map[string][]net.IP),
		allowed:   allowed,
		emit:      emit,
	}
	for _, st := range serviceTypes {
		st = strings.Trim(st, ".")
		if st == "" {
			continue
		}
		name := dns.Fqdn(st + "." + domain)
		if _, dup := s.wanted[name]; dup {
			continue
		}
		s.wanted[name] = st
		s.questions = append(s.questions, dns.Question{Name: name, Qtype: dns.TypePTR, Qclass: dns.ClassINET})
	}
	return s
}

// serviceOf returns the PTR owner name and service type an instance name
// belongs to, or empty strings. It peels labels off the front and looks for
// an exact match so the most specific (longest) owner wins deterministically,
// unlike a substring suffix scan over map keys in random iteration order
func (s *browseState) serviceOf(instanceName string) (string, string) {
	name := instanceName
	for {
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return "", ""
		}
		name = name[i+1:]
		if st, ok := s.wanted[name]; ok {
			return name, st
		}
	}
}

func (s *browseState) getInstance(name string, ifIndex int) *instState {
	if st, ok := s.instances[name]; ok {
		return st
	}
	owner, svc := s.serviceOf(name)
	if svc == "" {
		return nil
	}
	st := &instState{
		serviceType: svc,
		instance:    strings.TrimSuffix(name, "."+owner),
		ifIndex:     ifIndex,
		sentAddrs:   make(map[string]struct{}),
	}
	s.instances[name] = st
	return st
}

// followUps builds SRV/TXT questions for instances still lacking an SRV record
// and A/AAAA questions for hosts without any address yet. Most responders
// include these as additional records, so this is usually empty.
func (s *browseState) followUps() []dns.Question {
	var qs []dns.Question
	seenHost := make(map[string]struct{})
	for name, st := range s.instances {
		if !st.hasSRV {
			qs = append(qs, dns.Question{Name: name, Qtype: dns.TypeSRV, Qclass: dns.ClassINET})
			if !st.hasTXT {
				qs = append(qs, dns.Question{Name: name, Qtype: dns.TypeTXT, Qclass: dns.ClassINET})
			}
			continue
		}
		if len(s.hosts[st.host]) > 0 {
			continue
		}
		if _, dup := seenHost[st.host]; dup {
			continue
		}
		seenHost[st.host] = struct{}{}
		qs = append(qs, dns.Question{Name: st.host, Qtype: dns.TypeA, Qclass: dns.ClassINET})
		qs = append(qs, dns.Question{Name: st.host, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET})
	}
	return qs
}

// flush emits every completed (instance, address) pair not reported before.
func (s *browseState) flush() {
	for _, st := range s.instances {
		if !st.hasSRV {
			continue
		}
		addrs := s.hosts[st.host]
		if len(addrs) == 0 {
			continue
		}
		e := &mdnsEntry{
			ServiceType: st.serviceType,
			Instance:    st.instance,
			Domain:      s.domain,
			HostName:    st.host,
			Port:        st.port,
			Text:        st.txt,
			TTL:         st.ttl,
			IfIndex:     st.ifIndex,
		}
		for _, ip := range addrs {
			key := ip.String()
			if _, done := st.sentAddrs[key]; done {
				continue
			}
			st.sentAddrs[key] = struct{}{}
			if ip.To4() != nil {
				e.AddrIPv4 = append(e.AddrIPv4, ip)
			} else {
				e.AddrIPv6 = append(e.AddrIPv6, ip)
			}
		}
		if len(e.AddrIPv4)+len(e.AddrIPv6) > 0 && s.emit != nil {
			s.emit(e)
		}
	}
}

// handle folds one response packet into the state and emits new results.
func (s *browseState) handle(p mdnsPacket) {
	if len(s.allowed) > 0 && p.ifIndex != 0 {
		if _, ok := s.allowed[p.ifIndex]; !ok {
			return
		}
	}
	sections := make([]dns.RR, 0, len(p.msg.Answer)+len(p.msg.Ns)+len(p.msg.Extra))
	sections = append(sections, p.msg.Answer...)
	sections = append(sections, p.msg.Ns...)
	sections = append(sections, p.msg.Extra...)

	// Instances withdrawn by a goodbye PTR in this packet must not be recreated
	// by SRV/TXT records that appear alongside it.
	goodbye := make(map[string]struct{})
	for _, rr := range sections {
		switch r := rr.(type) {
		case *dns.PTR:
			if _, ok := s.wanted[r.Hdr.Name]; !ok {
				continue
			}
			if r.Hdr.Ttl == 0 {
				// Goodbye packet: forget the instance, keep what was already reported.
				delete(s.instances, r.Ptr)
				goodbye[r.Ptr] = struct{}{}
				continue
			}
			if _, gone := goodbye[r.Ptr]; gone {
				continue
			}
			if st := s.getInstance(r.Ptr, p.ifIndex); st != nil {
				st.ttl = r.Hdr.Ttl
			}
		case *dns.SRV:
			if _, gone := goodbye[r.Hdr.Name]; gone || r.Hdr.Ttl == 0 {
				continue
			}
			if st := s.getInstance(r.Hdr.Name, p.ifIndex); st != nil {
				st.host = dns.Fqdn(r.Target)
				st.port = int(r.Port)
				st.hasSRV = true
				if st.ttl == 0 {
					st.ttl = r.Hdr.Ttl
				}
			}
		case *dns.TXT:
			if _, gone := goodbye[r.Hdr.Name]; gone || r.Hdr.Ttl == 0 {
				continue
			}
			if st := s.getInstance(r.Hdr.Name, p.ifIndex); st != nil {
				st.txt = r.Txt
				st.hasTXT = true
			}
		}
	}
	for _, rr := range sections {
		var ip net.IP
		var name string
		switch r := rr.(type) {
		case *dns.A:
			ip, name = r.A, r.Hdr.Name
		case *dns.AAAA:
			ip, name = r.AAAA, r.Hdr.Name
		default:
			continue
		}
		if rr.Header().Ttl == 0 || ip == nil {
			continue
		}
		name = dns.Fqdn(name)
		dup := false
		for _, have := range s.hosts[name] {
			if have.Equal(ip) {
				dup = true
				break
			}
		}
		if !dup {
			s.hosts[name] = append(s.hosts[name], ip)
		}
	}
	s.flush()
}

// Browse loop

// browse queries all serviceTypes in domain until ctx ends, calling emit for
// every newly completed (instance, address) result. It returns errBrowseFailed
// (wrapped) if the very first query round could not be sent on any interface.
func (b *mdnsBrowser) browse(ctx context.Context, serviceTypes []string, domain string, allowed map[int]struct{}, emit func(*mdnsEntry)) error {
	state := newBrowseState(serviceTypes, domain, allowed, emit)
	if len(state.questions) == 0 {
		return fmt.Errorf("%w: no service types to query", errBrowseFailed)
	}

	// First round synchronously so a dead network surfaces as an error
	// instead of a silent timeout.
	n, err := b.sendQuestions(state.questions)
	if n == 0 {
		if err == nil {
			err = fmt.Errorf("no interface accepted the query")
		}
		return fmt.Errorf("%w: %v", errBrowseFailed, classifyBrowseError(err))
	}
	if b.debug {
		fmt.Fprintf(os.Stderr, "debug: query round sent (%d service types, %d datagrams)\n", len(state.questions), n)
	}

	packets := make(chan mdnsPacket, 64)
	if b.conn4 != nil {
		go b.recvLoop(ctx, 4, packets)
	}
	if b.conn6 != nil {
		go b.recvLoop(ctx, 6, packets)
	}

	interval := firstQueryInterval
	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case p := <-packets:
			state.handle(p)
		case <-timer.C:
			qs := append(append([]dns.Question(nil), state.questions...), state.followUps()...)
			n, err := b.sendQuestions(qs)
			if b.debug {
				fmt.Fprintf(os.Stderr, "debug: query round sent (%d questions, %d datagrams, err=%v)\n", len(qs), n, err)
			}
			interval *= 2
			if interval > maxQueryInterval {
				interval = maxQueryInterval
			}
			timer.Reset(interval)
		}
	}
}
