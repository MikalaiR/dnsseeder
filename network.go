package main

import (
	"fmt"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"net"
	"os"
)

type NetworkConfig struct {
	Name                 string             `yaml:"name"`
	ID                   wire.BitcoinNet    `yaml:"id"`
	Port                 uint16             `yaml:"port"`
	NetVer               uint32             `yaml:"network_version"`
	DNSName              string             `yaml:"dns_name"`
	DNSServer            string             `yaml:"dns_server"`
	TTL                  uint32             `yaml:"ttl"`
	InitialIPs           []net.IP           `yaml:"initial_nodes"`
	Seeders              []string           `yaml:"seeders"`
	AllowedServiceFilter []wire.ServiceFlag `yaml:"allowed_service_filters"`
	SOAMbox              string             `yaml:"soa_mbox"`
	log                  *log.Entry
}

func loadNetwork(fName string) (*DNSSeeder, error) {
	f, err := os.Open(fName)
	if err != nil {
		return nil, fmt.Errorf("error opening config file: %v", err)
	}

	defer f.Close()

	seeder := &DNSSeeder{}

	decoder := yaml.NewDecoder(f)
	if err = decoder.Decode(&seeder.NetworkConfig); err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}

	if seeder.Port == 0 {
		return nil, fmt.Errorf("invalid port supplied: %v", seeder.Port)

	}

	if seeder.DNSName == "" {
		return nil, fmt.Errorf("no DNS Hostname supplied")
	}

	// init the seeder
	seeder.nodes = make(map[string]*node)

	// add some checks to the start & delay values to keep them sane
	seeder.maxStart = []uint32{20, 20, 20, 30}
	seeder.delay = []int64{210, 789, 234, 1876}
	seeder.maxSize = 1250

	if seeder.TTL < 60 {
		seeder.TTL = 60
	}

	if dup, err := isDuplicateSeeder(seeder); dup == true {
		return nil, err
	}

	seeder.dns = newEmptyDNSState()
	seeder.log = log.WithField("network", seeder.Name)

	return seeder, nil
}
