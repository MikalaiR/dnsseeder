package main

import (
	"fmt"
	"github.com/btcsuite/btcd/wire"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"strconv"
	"time"
)

func makeSOA(s *DNSSeeder, question *dns.Question) dns.RR {
	soa := &dns.SOA{}
	soa.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: s.TTL}
	soa.Serial = uint32(time.Now().Unix())
	soa.Ns = s.DNSServer
	soa.Mbox = s.SOAMbox
	soa.Refresh = 604800
	soa.Retry = 86400
	soa.Expire = 2592000
	soa.Minttl = 604800
	return soa
}

func makeRR(s *DNSSeeder, name string, node *node) dns.RR {
	switch node.dnsType {
	case dns.TypeA:
		r := &dns.A{}
		r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.TTL}
		r.A = node.na.IP
		return r
	case dns.TypeAAAA:
		r := &dns.AAAA{}
		r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: s.TTL}
		r.AAAA = node.na.IP
		return r
	}
	return nil
}

// updateDNS updates the current slices of dns.RR so incoming requests get a
// fast answer
func updateDNS(s *DNSSeeder) {
	s.mtx.RLock()

	newState := newEmptyDNSState()
	for _, node := range s.nodes {
		if node.status != statusCG {
			continue
		}

		if len(newState.ByServices[node.dnsType][0]) < 25 {
			newState.ByServices[node.dnsType][0] =
				append(newState.ByServices[node.dnsType][0], makeRR(s, s.DNSName, node))
		}

		for _, svc := range s.AllowedServiceFilter {
			if len(newState.ByServices[node.dnsType][svc]) < 25 && node.na.HasService(svc) {
				newState.ByServices[node.dnsType][svc] =
					append(newState.ByServices[node.dnsType][svc], makeRR(s, fmt.Sprintf("x%x.%s", int(svc), s.DNSName), node))
			}
		}
	}

	s.mtx.RUnlock()

	s.dnsLock.Lock()
	s.dns = newState
	s.dnsLock.Unlock()
}

func wrapHandler(s *DNSSeeder) dns.HandlerFunc {
	return func(w dns.ResponseWriter, msg *dns.Msg) {
		m := &dns.Msg{MsgHdr: dns.MsgHdr{
			Authoritative:      true,
			RecursionAvailable: false,
		}}
		m.SetReply(msg)

		question := msg.Question[0]

		ns := &dns.NS{}
		ns.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: s.TTL}
		ns.Ns = s.DNSServer

		s.dnsLock.RLock()
		dnsState := s.dns.ByServices[question.Qtype]
		s.dnsLock.RUnlock()

		switch question.Qtype {
		case dns.TypeA, dns.TypeAAAA:
			if question.Name[0] == 'x' {
				filter, _ := strconv.ParseUint(question.Name[1:2], 16, 16)
				m.Answer = dnsState[wire.ServiceFlag(filter)]
			} else {
				m.Answer = dnsState[0]
			}
		case dns.TypeNS:
			m.Answer = append(m.Answer, ns)
		case dns.TypeSOA:
			m.Answer = append(m.Answer, makeSOA(s, &question))
		case dns.TypeANY:
			hi := &dns.HINFO{}
			hi.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: s.TTL}
			hi.Cpu = "ANY obsoleted"
			hi.Os = "See draft-ietf-dnsop-refuse-any"
			m.Answer = append(m.Answer, hi)
		}

		if len(m.Answer) == 0 {
			m.Ns = append(m.Ns, makeSOA(s, &question))
		} else {
			m.Ns = append(m.Ns, ns)
		}

		err := w.WriteMsg(m)

		if err != nil {
			s.log.Debugf("Cannot send DNS response: %v", err)
		}
	}
}

func dnsInitSeeder(seeder *DNSSeeder) {
	dns.HandleFunc(seeder.DNSName, wrapHandler(seeder))
}

func serve(net, listen string) {
	server := &dns.Server{Addr: listen, Net: net, TsigSecret: nil}
	if err := server.ListenAndServe(); err != nil {
		log.Errorf("Failed to setup %s server: %v", net, err)
	}
}
