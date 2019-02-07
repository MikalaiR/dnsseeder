package main

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/btcsuite/btcd/wire"
)

const (
	// NOUNCE is used to check if we connect to ourselves
	// as we don't listen we can use a fixed value
	nounce = 0x0539a019ca550825

	crawlDelay = 22 // seconds between start crawlwer ticks
	auditDelay = 22 // minutes between audit channel ticks
	dnsDelay   = 57 // seconds between updates to active dns record list

	maxFails = 58 // max number of connect fails before we delete a node. Just over 24 hours(checked every 33 minutes)

	maxTo = 250 // max seconds (4min 10 sec) for all comms to node to complete before we timeout
)

const (
	// node status
	statusRG       = iota // reported good status. A remote node has reported this ip but we have not connected
	statusCG              // confirmed good. We have connected to the node and received addresses
	statusWG              // was good. node was confirmed good but now having problems
	statusNG              // no good. Will be removed from nodes after 24 hours to redure bouncing ip addresses
	maxStatusTypes        // used in main to allocate slice
)

type dnsState struct {
	ByServices map[uint16]map[wire.ServiceFlag][]dns.RR
}

func newEmptyDNSState() *dnsState {
	newState := &dnsState{}
	newState.ByServices = make(map[uint16]map[wire.ServiceFlag][]dns.RR)
	newState.ByServices[dns.TypeAAAA] = make(map[wire.ServiceFlag][]dns.RR)
	newState.ByServices[dns.TypeA] = make(map[wire.ServiceFlag][]dns.RR)
	return newState
}

type DNSSeeder struct {
	NetworkConfig
	nodes    map[string]*node // the list of current nodes
	mtx      sync.RWMutex     // protect thelist
	maxStart []uint32         // max number of goroutines to start each run for each status type
	delay    []int64          // number of seconds to wait before we connect to a known client for each status
	maxSize  int              // max number of clients before we start restricting new entries
	dns      *dnsState
	dnsLock  sync.RWMutex
}

type result struct {
	nas      []*wire.NetAddress // slice of node addresses returned from a node
	msg      error              // error string or nil if no problems
	node     string             // nodes key to the node that was crawled
	version  int32              // remote node protocol version
	services wire.ServiceFlag   // remote client supported services
}

// initCrawlers needs to be run before the startCrawlers so it can get
// a list of current ip addresses from the other seeders and therefore
// start the crawl process
func (s *DNSSeeder) initSeeder() {

	for _, seed := range s.Seeders {
		addrs, err := net.LookupIP(seed)
		if err != nil {
			s.log.Errorf("Unable to do initial lookup to seeder %s: %v", seed, err)
			continue
		}

		s.log.Infof("Loaded %d addresses from %s", len(addrs), seed)

		for _, ip := range addrs {
			s.addNa(wire.NewNetAddressIPPort(ip, s.Port, 0))
		}
	}

	// load ip addresses into system and start crawling from it
	if len(s.nodes) == 0 && len(s.InitialIPs) > 0 {
		for _, ip := range s.InitialIPs {
			s.addNa(wire.NewNetAddressIPPort(ip, s.Port, 0))
		}
	}

	if len(s.nodes) == 0 {
		s.log.Error("No ip addresses found")
	}
}

// runSeeder runs a seeder in an endless goroutine
func (s *DNSSeeder) runSeeder(done <-chan struct{}, wg *sync.WaitGroup) {

	defer wg.Done()

	// receive the results from the crawl goroutines
	resultsChan := make(chan *result)

	// load data from other seeders so we can start crawling nodes
	s.initSeeder()

	// start initial scan now so we don't have to wait for the timers to fire
	s.startCrawlers(resultsChan)

	// create timing channels for regular tasks
	auditChan := time.NewTicker(time.Minute * auditDelay).C
	crawlChan := time.NewTicker(time.Second * crawlDelay).C
	dnsChan := time.NewTicker(time.Second * dnsDelay).C

	for {
		select {
		case r := <-resultsChan:
			// process a results structure from a crawl
			s.processResult(r)
		case <-dnsChan:
			// update the system with the latest selection of dns records
			s.loadDNS()
		case <-auditChan:
			// keep nodes clean and tidy
			s.auditNodes()
		case <-crawlChan:
			// start a scan to crawl nodes
			s.startCrawlers(resultsChan)
		case <-done:
			// done channel closed so exit the select and shutdown the seeder
			s.log.Infof("Shutting down seeder")
			return
		}
	}
}

// startCrawlers is called on a time basis to start maxcrawlers new
// goroutines if there are spare goroutine slots available
func (s *DNSSeeder) startCrawlers(resultsChan chan *result) {

	s.mtx.RLock()
	defer s.mtx.RUnlock()

	tcount := uint32(len(s.nodes))
	if tcount == 0 {
		return
	}

	started := make([]uint32, maxStatusTypes)
	totals := make([]uint32, maxStatusTypes)

	// range on a map will not return items in the same order each time
	// so this is a random'ish selection
	for _, nd := range s.nodes {

		totals[nd.status]++

		if nd.crawlActive == true {
			continue
		}

		// do we already have enough started at this status
		if started[nd.status] >= s.maxStart[nd.status] {
			continue
		}

		// don't crawl a node to quickly
		if (time.Now().Unix() - s.delay[nd.status]) <= nd.lastTry.Unix() {
			continue
		}

		// all looks good so start a go routine to crawl the remote node
		nd.crawlActive = true

		go crawlNode(resultsChan, s, nd)
		started[nd.status]++
	}
}

// processResult will add new nodes to the list and update the status of the crawled node
func (s *DNSSeeder) processResult(r *result) {

	var nd *node

	s.mtx.Lock()
	defer s.mtx.Unlock()

	if _, ok := s.nodes[r.node]; ok {
		nd = s.nodes[r.node]
	} else {
		s.log.Warnf("Ignoring results from unknown node: %s", r.node)
		return
	}

	// now nd has been set to a valid pointer we can use it in a defer
	defer crawlEnd(nd)

	// msg is a crawlerror or nil
	if r.msg != nil {
		// update the fact that we have not connected to this node
		nd.lastTry = time.Now()
		nd.connectFails++

		// update the status of this failed node
		switch nd.status {
		case statusRG:
			// if we are full then any RG failures will skip directly to NG
			if len(s.nodes) > s.maxSize {
				nd.status = statusNG // not able to connect to this node so ignore
			} else {
				if nd.rating += 25; nd.rating > 30 {
					nd.status = statusWG
				}
			}
		case statusCG:
			if nd.rating += 25; nd.rating >= 50 {
				nd.status = statusWG
			}
		case statusWG:
			if nd.rating += 15; nd.rating >= 100 {
				nd.status = statusNG // not able to connect to this node so ignore
			}
		}
		// no more to do so return which will shutdown the goroutine & call
		// the deffered cleanup
		s.log.Debugf("Failed crawl node %s: %v", nd.na.IP, r.msg)

		return
	}

	// succesful connection and addresses received so mark status
	nd.status = statusCG
	nd.rating = 0
	nd.connectFails = 0
	nd.na.Timestamp = time.Now()
	nd.lastTry = nd.na.Timestamp
	nd.na.Services = r.services

	added := 0

	// if we are full then skip adding more possible clients
	if len(s.nodes) < s.maxSize {
		// do not accept more than one third of maxSize addresses from one node
		oneThird := int(float64(s.maxSize / 3))

		// loop through all the received network addresses and add to thelist if not present
		for _, na := range r.nas {
			// a new network address so add to the system
			if x := s.addNa(na); x == true {
				if added++; added > oneThird {
					break
				}
			}
		}
	}

	s.log.Debugf("Crawl %s done: added %d nodes", nd.na.IP, added)
}

// crawlEnd is run as a defer to make sure node status is correctly updated
func crawlEnd(nd *node) {
	nd.crawlActive = false
}

// addNa validates and adds a network address to nodes
func (s *DNSSeeder) addNa(nNa *wire.NetAddress) bool {

	if len(s.nodes) > s.maxSize {
		return false
	}

	if nNa.Port != s.Port {
		return false
	}

	// generate the key and add to nodes
	k := net.JoinHostPort(nNa.IP.String(), strconv.Itoa(int(nNa.Port)))

	if _, dup := s.nodes[k]; dup == true {
		return false
	}

	// if the reported timestamp suggests the netaddress has not been seen in the last 24 hours
	// then ignore this netaddress
	if (time.Now().Add(-(time.Hour * 24))).After(nNa.Timestamp) {
		return false
	}

	nt := node{
		na:      nNa,
		status:  statusRG,
		dnsType: dns.TypeA,
	}

	// select the dns type based on the remote address type and port
	if x := nt.na.IP.To4(); x == nil {
		nt.dnsType = dns.TypeAAAA
	}

	// add the new node details to nodes
	s.nodes[k] = &nt

	return true
}

func (s *DNSSeeder) auditNodes() {

	count := len(s.nodes)

	// set this early so for this audit run all NG clients will be purged
	// and space will be made for new, possible CG clients
	iAmFull := count > s.maxSize

	// cgGoal is 75% of the max statusCG clients we can crawl with the current network delay & maxStart settings.
	// This allows us to cycle statusCG users to keep the list fresh
	cgGoal := int(float64(float64(s.delay[statusCG]/crawlDelay)*float64(s.maxStart[statusCG])) * 0.75)
	cgCount := 0

	s.mtx.Lock()
	defer s.mtx.Unlock()

	for k, nd := range s.nodes {

		if nd.crawlActive == true {

		}

		// Audit task is to remove node that we have not been able to connect to
		if nd.status == statusNG && nd.connectFails > maxFails {
			s.log.Warnf("Purging node %s after %v failed connections", k, nd.connectFails)

			// remove the map entry and mark the old node as
			// nil so garbage collector will remove it
			s.nodes[k] = nil
			delete(s.nodes, k)
		}

		// If seeder is full then remove old NG clients and fill up with possible new CG clients
		if nd.status == statusNG && iAmFull {
			s.log.Warnf("Seeder full purging node %s", k)

			// remove the map entry and mark the old node as
			// nil so garbage collector will remove it
			s.nodes[k] = nil
			delete(s.nodes, k)
		}

		// check if we need to purge statusCG to freshen the list
		if nd.status == statusCG {
			if cgCount++; cgCount > cgGoal {
				// we have enough statusCG clients so purge remaining to cycle through the list
				s.log.Infof("Seeder cycle statusCG - purging node %s", k)

				// remove the map entry and mark the old node as
				// nil so garbage collector will remove it
				s.nodes[k] = nil
				delete(s.nodes, k)
			}
		}
	}
	s.log.Infof("Audit complete. %v nodes purged.", count-len(s.nodes))
}

// teatload loads the dns records with time based test data
func (s *DNSSeeder) loadDNS() {
	updateDNS(s)
}

// isDuplicateSeeder returns true if the seeder details already exist in the application
func isDuplicateSeeder(s *DNSSeeder) (bool, error) {
	for _, v := range config.seeders {
		if v.ID == s.ID {
			return true, fmt.Errorf("duplicate Magic id %v. Already loaded for %s so can not be used for %s", v.ID, v.Name, s.Name)
		}
		if v.DNSName == s.DNSName {
			return true, fmt.Errorf("duplicate DNS names. Already loaded %s for %s so can not be used for %s", v.DNSName, v.Name, s.Name)
		}
	}
	return false, nil
}
