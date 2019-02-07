package main

import (
	"fmt"
	"github.com/btcsuite/btcd/wire"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"strconv"
	"time"
)

// updateDNS updates the current slices of dns.RR so incoming requests get a
// fast answer
func updateDNS(s *DNSSeeder) {
	s.mtx.RLock()

	newState := newEmptyDNSState()
	for _, node := range s.nodes {
		if node.status != statusCG {
			continue
		}

		switch node.dnsType {
		case dns.TypeA:
			r := &dns.A{}
			r.Hdr = dns.RR_Header{Name: s.DNSName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.TTL}
			r.A = node.na.IP

			if len(newState.ByServices[dns.TypeA][0]) < 25 {
				newState.ByServices[dns.TypeA][0] = append(newState.ByServices[dns.TypeA][0], r)
			}

			for _, svc := range s.AllowedServiceFilter {
				if node.services&svc != 0 && len(newState.ByServices[dns.TypeA][svc]) < 25 {

					r2 := &dns.A{}
					r2.Hdr = dns.RR_Header{
						Name:   fmt.Sprintf("x%x.%s", svc, s.DNSName),
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    s.TTL,
					}

					r2.A = node.na.IP

					newState.ByServices[dns.TypeA][svc] = append(newState.ByServices[dns.TypeA][svc], r2)
				}
			}
		case dns.TypeAAAA:
			r := &dns.AAAA{}
			r.Hdr = dns.RR_Header{Name: s.DNSName, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: s.TTL}
			r.AAAA = node.na.IP

			if len(newState.ByServices[dns.TypeAAAA][0]) < 25 {
				newState.ByServices[dns.TypeAAAA][0] = append(newState.ByServices[dns.TypeAAAA][0], r)
			}

			for _, svc := range s.AllowedServiceFilter {
				if node.services&svc != 0 && len(newState.ByServices[dns.TypeA][svc]) < 25 {

					r2 := &dns.AAAA{}
					r2.Hdr = dns.RR_Header{
						Name:   fmt.Sprintf("x%x.%s", svc, s.DNSName),
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    s.TTL,
					}

					r2.AAAA = node.na.IP
					newState.ByServices[dns.TypeAAAA][svc] = append(newState.ByServices[dns.TypeAAAA][svc], r2)
				}
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

		soa := &dns.SOA{}
		soa.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: s.TTL}
		soa.Serial = uint32(time.Now().Unix())
		soa.Ns = s.DNSServer
		soa.Mbox = s.SOAMbox
		soa.Refresh = 604800
		soa.Retry = 86400
		soa.Expire = 2592000
		soa.Minttl = 604800

		if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
			s.dnsLock.RLock()
			if question.Name[0] == 'x' {
				filter, _ := strconv.ParseUint(question.Name[1:2], 16, 16)
				m.Answer = s.dns.ByServices[question.Qtype][wire.ServiceFlag(filter)]
			} else {
				m.Answer = s.dns.ByServices[question.Qtype][0]
			}
			s.dnsLock.RUnlock()
		} else if question.Qtype == dns.TypeNS {
			m.Answer = append(m.Answer, ns)
		} else if question.Qtype == dns.TypeSOA {
			m.Answer = append(m.Answer, soa)
		}

		if len(m.Answer) == 0 {
			m.Ns = append(m.Ns, soa)
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
