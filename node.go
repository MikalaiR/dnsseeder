package main

import (
	"github.com/btcsuite/btcd/wire"
	"time"
)

type node struct {
	na           *wire.NetAddress // holds ip address & port details
	lastConnect  time.Time        // last time we sucessfully connected to this client
	lastTry      time.Time        // last time we tried to connect to this client
	services     wire.ServiceFlag // remote client supported services
	connectFails uint32           // number of times we have failed to connect to this client
	status       uint32           // rg,cg,wg,ng
	rating       uint32           // if it reaches 100 then we mark them statusNG
	dnsType      uint16           // what dns type this client is
	crawlActive  bool             // are we currently crawling this client
}
