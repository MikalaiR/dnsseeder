/*

 */
package main

import (
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

// configData holds information on the application
type configData struct {
	listen   string                // port for the dns server to listen on
	seeders  map[string]*DNSSeeder // holds a pointer to all the current seeders
	loglevel string                // debug cmdline option
}

var config configData
var netfile string

func main() {
	flag.StringVar(&netfile, "netfile", "", "List of json config files to load")
	flag.StringVar(&config.listen, "listen", ":53", "Addr to listen on")
	flag.StringVar(&config.loglevel, "loglevel", "warn", "Log level")
	flag.Parse()

	level, err := log.ParseLevel(config.loglevel)
	if err != nil {
		log.SetLevel(log.WarnLevel)
	} else {
		log.SetLevel(level)
	}

	// configure the network options so we can start crawling
	netwFiles := strings.Split(netfile, ",")
	if len(netwFiles) == 0 {
		fmt.Printf("Error - No filenames specified. Please add -net=<file[, file2]> to load these files\n")
		os.Exit(1)
	}

	config.seeders = make(map[string]*DNSSeeder)

	for _, v := range netwFiles {
		net, err := loadNetwork(v)
		if err != nil {
			fmt.Printf("Error loading data from netfile %s - %v\n", net, err)
			os.Exit(1)
		}

		dnsInitSeeder(net)
		config.seeders[net.Name] = net
		log.Printf("status - system is configured for network: %s\n", net.Name)
	}

	// start dns server
	// dns.HandleFunc(".", handleDNS)
	go serve("udp", config.listen)
	go serve("tcp", config.listen)

	var wg sync.WaitGroup

	done := make(chan struct{})
	// start a goroutine for each seeder
	for _, s := range config.seeders {
		wg.Add(1)
		go s.runSeeder(done, &wg)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// block until a signal is received
	log.Infof("Shutting down on signal: %v", <-sig)

	// FIXME - call dns server.Shutdown()

	// close the done channel to signal to all seeders to shutdown
	// and wait for them to exit
	close(done)
	wg.Wait()
}
