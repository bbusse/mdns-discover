// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func hdr(name string, t uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: ttl}
}

func ptr(owner, target string, ttl uint32) dns.RR {
	return &dns.PTR{Hdr: hdr(owner, dns.TypePTR, ttl), Ptr: target}
}
func srv(name, target string, port uint16) dns.RR {
	return &dns.SRV{Hdr: hdr(name, dns.TypeSRV, 120), Target: target, Port: port}
}
func txt(name string, t ...string) dns.RR {
	return &dns.TXT{Hdr: hdr(name, dns.TypeTXT, 4500), Txt: t}
}
func a(name, ip string) dns.RR {
	return &dns.A{Hdr: hdr(name, dns.TypeA, 120), A: net.ParseIP(ip).To4()}
}
func aaaa(name, ip string) dns.RR {
	return &dns.AAAA{Hdr: hdr(name, dns.TypeAAAA, 120), AAAA: net.ParseIP(ip)}
}

func response(answer []dns.RR, extra []dns.RR) mdnsPacket {
	m := new(dns.Msg)
	m.Response = true
	m.Answer = answer
	m.Extra = extra
	return mdnsPacket{msg: m, ifIndex: 7}
}

func collect(t *testing.T, types []string, allowed map[int]struct{}) (*browseState, *[]*mdnsEntry) {
	t.Helper()
	var got []*mdnsEntry
	s := newBrowseState(types, "local", allowed, func(e *mdnsEntry) { got = append(got, e) })
	return s, &got
}

func TestSinglePacketWithAdditionals(t *testing.T) {
	s, got := collect(t, []string{"_ssh._tcp"}, nil)
	s.handle(response(
		[]dns.RR{ptr("_ssh._tcp.local.", "box._ssh._tcp.local.", 4500)},
		[]dns.RR{
			srv("box._ssh._tcp.local.", "box.local.", 22),
			txt("box._ssh._tcp.local.", "k=v"),
			a("box.local.", "192.168.1.10"),
			aaaa("box.local.", "fe80::1"),
		},
	))
	if len(*got) != 1 {
		t.Fatalf("want 1 emit, got %d", len(*got))
	}
	e := (*got)[0]
	if e.ServiceType != "_ssh._tcp" || e.Instance != "box" || e.HostName != "box.local." || e.Port != 22 {
		t.Errorf("unexpected entry %+v", e)
	}
	if len(e.AddrIPv4) != 1 || len(e.AddrIPv6) != 1 || e.AddrIPv4[0].String() != "192.168.1.10" {
		t.Errorf("addresses %v %v", e.AddrIPv4, e.AddrIPv6)
	}
	if e.TTL != 4500 || e.IfIndex != 7 || len(e.Text) != 1 || e.Text[0] != "k=v" {
		t.Errorf("meta %+v", e)
	}
	// Same packet again must not emit anything new.
	s.handle(response([]dns.RR{ptr("_ssh._tcp.local.", "box._ssh._tcp.local.", 4500)}, []dns.RR{
		srv("box._ssh._tcp.local.", "box.local.", 22), a("box.local.", "192.168.1.10")}))
	if len(*got) != 1 {
		t.Fatalf("duplicate emitted: %d", len(*got))
	}
}

func TestAddressesArrivingLater(t *testing.T) {
	s, got := collect(t, []string{"_http._tcp"}, nil)
	s.handle(response([]dns.RR{ptr("_http._tcp.local.", "cam._http._tcp.local.", 4500)},
		[]dns.RR{srv("cam._http._tcp.local.", "cam.local.", 80)}))
	if len(*got) != 0 {
		t.Fatalf("emitted without address")
	}
	fu := s.followUps()
	if len(fu) != 2 || fu[0].Name != "cam.local." || fu[0].Qtype != dns.TypeA || fu[1].Qtype != dns.TypeAAAA {
		t.Fatalf("follow-ups %+v", fu)
	}
	s.handle(response([]dns.RR{a("cam.local.", "10.0.0.5")}, nil))
	if len(*got) != 1 || (*got)[0].AddrIPv4[0].String() != "10.0.0.5" {
		t.Fatalf("after A: %+v", *got)
	}
	s.handle(response([]dns.RR{aaaa("cam.local.", "2001:db8::5")}, nil))
	if len(*got) != 2 || len((*got)[1].AddrIPv4) != 0 || (*got)[1].AddrIPv6[0].String() != "2001:db8::5" {
		t.Fatalf("after AAAA: %+v", *got)
	}
	if len(s.followUps()) != 0 {
		t.Errorf("follow-ups should be empty once resolved")
	}
}

func TestSRVWithoutPTRStillResolves(t *testing.T) {
	s, got := collect(t, []string{"_ssh._tcp", "_sftp-ssh._tcp"}, nil)
	s.handle(response([]dns.RR{
		srv("nas._sftp-ssh._tcp.local.", "nas.local.", 22),
		a("nas.local.", "10.0.0.9"),
	}, nil))
	if len(*got) != 1 || (*got)[0].ServiceType != "_sftp-ssh._tcp" || (*got)[0].Instance != "nas" {
		t.Fatalf("got %+v", *got)
	}
}

func TestUnwantedAndGoodbyeIgnored(t *testing.T) {
	s, got := collect(t, []string{"_ssh._tcp"}, nil)
	s.handle(response([]dns.RR{ptr("_ipp._tcp.local.", "pr._ipp._tcp.local.", 4500)},
		[]dns.RR{srv("pr._ipp._tcp.local.", "pr.local.", 631), a("pr.local.", "10.0.0.2")}))
	s.handle(response([]dns.RR{ptr("_ssh._tcp.local.", "gone._ssh._tcp.local.", 0)},
		[]dns.RR{srv("gone._ssh._tcp.local.", "gone.local.", 22), a("gone.local.", "10.0.0.3")}))
	if len(*got) != 0 || len(s.instances) != 0 {
		t.Fatalf("got %d emits, %d instances", len(*got), len(s.instances))
	}
	if len(s.followUps()) != 0 {
		t.Errorf("no follow-ups expected")
	}
}

func TestInterfaceFilter(t *testing.T) {
	s, got := collect(t, []string{"_ssh._tcp"}, map[int]struct{}{3: {}})
	p := response([]dns.RR{ptr("_ssh._tcp.local.", "box._ssh._tcp.local.", 4500)},
		[]dns.RR{srv("box._ssh._tcp.local.", "box.local.", 22), a("box.local.", "10.0.0.1")})
	s.handle(p) // ifIndex 7, filtered
	if len(*got) != 0 {
		t.Fatalf("filtered packet emitted")
	}
	p.ifIndex = 3
	s.handle(p)
	if len(*got) != 1 || (*got)[0].IfIndex != 3 {
		t.Fatalf("allowed packet: %+v", *got)
	}
}

func TestPackQuestionsChunking(t *testing.T) {
	s := newBrowseState(services[:], "local", nil, nil)
	unique := make(map[string]struct{})
	for _, svc := range services {
		unique[svc] = struct{}{}
	}
	if len(s.questions) != len(unique) {
		t.Fatalf("questions %d != unique services %d", len(s.questions), len(unique))
	}
	bufs := packQuestions(s.questions)
	if len(bufs) < 2 {
		t.Fatalf("expected several datagrams for %d questions, got %d", len(s.questions), len(bufs))
	}
	total := 0
	for i, b := range bufs {
		if len(b) > maxQueryBytes {
			t.Errorf("datagram %d is %d bytes > %d", i, len(b), maxQueryBytes)
		}
		m := new(dns.Msg)
		if err := m.Unpack(b); err != nil {
			t.Fatalf("unpack %d: %v", i, err)
		}
		if m.Response || m.RecursionDesired {
			t.Errorf("datagram %d has wrong flags", i)
		}
		total += len(m.Question)
	}
	if total != len(s.questions) {
		t.Errorf("questions across datagrams %d != %d", total, len(s.questions))
	}
	t.Logf("%d service types packed into %d datagrams", len(s.questions), len(bufs))
}
