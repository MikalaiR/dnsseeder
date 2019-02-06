package main

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/wire"
)

// crawlNode runs in a goroutine, crawls the remote ip and updates the master
// list of currently active addresses
func crawlNode(rc chan *result, s *DNSSeeder, nd *node) {

	res := &result{
		node: net.JoinHostPort(nd.na.IP.String(), strconv.Itoa(int(nd.na.Port))),
	}

	// connect to the remote ip and ask them for their addr list
	res.nas, res.msg = crawlIP(s, res)

	// all done so push the result back to the seeder.
	//This will block until the seeder reads the result
	rc <- res
}

// crawlIP retrievs a slice of ip addresses from a client
func crawlIP(s *DNSSeeder, r *result) ([]*wire.NetAddress, error) {
	conn, err := net.DialTimeout("tcp", r.node, time.Second*10)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to remote node: %v", err)
	}

	defer func() {
		err := conn.Close()
		if err != nil {
			s.log.Warnf("Error disconnecting from %s: %v", r.node, err)
		} else {
			s.log.Debugf("Successfully disconnected from %s", r.node)
		}
	}()

	s.log.Debugf("Connected to remote address %v", r.node)

	err = conn.SetDeadline(time.Now().Add(time.Second * maxTo))
	if err != nil {
		return nil, fmt.Errorf("cannot set connection deadline: %v", err)
	}

	msgver := wire.NewMsgVersion(&wire.NetAddress{}, &wire.NetAddress{}, nounce, 0)
	msgver.AddService(wire.SFNodeNetwork | wire.SFNodeWitness | wire.SFNodeBloom)

	err = wire.WriteMessage(conn, msgver, s.NetVer, s.ID)
	if err != nil {
		return nil, fmt.Errorf("cannot send version message: %v", err)
	}

	msg, _, err := wire.ReadMessage(conn, s.NetVer, s.ID)
	if err != nil {
		return nil, fmt.Errorf("cannot receive Ver message: %v", err)
	}

	switch msg := msg.(type) {
	case *wire.MsgVersion:
		s.log.Debugf("Node %s version is %d (%s), services is %d", r.node, msg.ProtocolVersion, msg.UserAgent, msg.Services)

		r.version = msg.ProtocolVersion
		r.services = msg.Services
	default:
		return nil, fmt.Errorf("did not receive Version message from remote node")
	}

	msgverack := wire.NewMsgVerAck()

	err = wire.WriteMessage(conn, msgverack, s.NetVer, s.ID)
	if err != nil {
		return nil, fmt.Errorf("cannot send VerAck message: %v", err)
	}

	msg, _, err = wire.ReadMessage(conn, s.NetVer, s.ID)
	if err != nil {
		return nil, fmt.Errorf("cannot receive VerAck message: %v", err)
	}

	switch msg.(type) {
	case *wire.MsgVerAck:
		s.log.Debugf("Received VerAck from %s", r.node)
	default:
		return nil, fmt.Errorf("did not receive VerAck message from remote node")
	}

	// if we get this far and if the seeder is full then don't ask for addresses. This will reduce bandwith usage while still
	// confirming that we can connect to the remote node
	/* if len(s.nodes) > s.maxSize {
		return nil, nil
	}*/
	// send getaddr command

	msgGetAddr := wire.NewMsgGetAddr()
	err = wire.WriteMessage(conn, msgGetAddr, s.NetVer, s.ID)
	if err != nil {
		return nil, fmt.Errorf("cannot send GetAddr message: %v", err)
	}

	for i := 0; i < 25; i++ {
		msgaddr, _, err := wire.ReadMessage(conn, s.NetVer, s.ID)
		if err != nil {
			s.log.Debugf("cannot receive message: %v; %v", err, msgaddr)
			if msgaddr == nil {
				return nil, fmt.Errorf("cannot receive message: %v", err)
			}
		}

		switch msg := msgaddr.(type) {
		case *wire.MsgAddr:
			s.log.Debugf("Received Addr message from %v", r.node)
			return msg.AddrList, nil

		case *wire.MsgPing:
			msgPong := wire.NewMsgPong(msg.Nonce)
			err = wire.WriteMessage(conn, msgPong, s.NetVer, s.ID)
			if err != nil {
				return nil, fmt.Errorf("cannot send Pong message: %v", err)
			}
		default:
			s.log.Debugf("Received unexpected %v message from %v", msg.Command(), r.node)
		}
	}

	return nil, fmt.Errorf("didn't receive Addr message in first 25 messages")
}
