// Package scanner performs periodic ARP discovery of hosts on the local
// network and records them into the device database.
package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/arp"

	"lanmonitor/internal/db"
)

// OfflineAfter is how long a device may go unseen before it is marked offline.
const OfflineAfter = 90 * time.Second

// Scanner performs periodic ARP sweeps of the configured interface's subnet.
type Scanner struct {
	DB       *db.DB
	Iface    *net.Interface
	Subnet   *net.IPNet
	Interval time.Duration

	// OnUpdate is invoked (if non-nil) whenever the device table changes,
	// typically wired up to broadcast a Server-Sent Event to the UI.
	OnUpdate func()
}

// New builds a Scanner bound to ifaceName (or the first viable interface if
// ifaceName is empty).
func New(database *db.DB, ifaceName string, interval time.Duration) (*Scanner, error) {
	ifi, ipnet, err := pickInterface(ifaceName)
	if err != nil {
		return nil, err
	}
	log.Printf("scanner: using interface %s (%s)", ifi.Name, ipnet.String())
	return &Scanner{
		DB:       database,
		Iface:    ifi,
		Subnet:   ipnet,
		Interval: interval,
	}, nil
}

// Run blocks, performing a scan immediately and then every s.Interval, until
// ctx is cancelled.
func (s *Scanner) Run(ctx context.Context) {
	s.runOnce()
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runOnce()
		}
	}
}

func (s *Scanner) runOnce() {
	if err := s.scan(); err != nil {
		log.Printf("scanner: scan error: %v", err)
	}
	stale := time.Now().UTC().Add(-OfflineAfter)
	changed, err := s.DB.MarkOfflineStaleSince(stale)
	if err != nil {
		log.Printf("scanner: mark offline error: %v", err)
	}
	if len(changed) > 0 && s.OnUpdate != nil {
		s.OnUpdate()
	}
}

func (s *Scanner) scan() error {
	c, err := arp.Dial(s.Iface)
	if err != nil {
		return fmt.Errorf("dial arp: %w", err)
	}
	defer c.Close()

	targets := hostAddrs(s.Subnet)
	if len(targets) == 0 {
		return nil
	}

	const listenWindow = 4 * time.Second
	if err := c.SetReadDeadline(time.Now().Add(listenWindow)); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}

	replies := make(chan *arp.Packet, 64)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			pkt, _, err := c.Read()
			if err != nil {
				return // deadline reached or socket closed
			}
			if pkt.Operation == arp.OperationReply {
				replies <- pkt
			}
		}
	}()

	go func() {
		for _, ip := range targets {
			_ = c.Request(ip)
			time.Sleep(2 * time.Millisecond) // pace requests, avoid bursts
		}
	}()

	updated := false
	for {
		select {
		case pkt := <-replies:
			mac := pkt.SenderHardwareAddr.String()
			ip := pkt.SenderIP.String()
			vendor := LookupVendor(mac)
			if _, err := s.DB.UpsertSeen(mac, ip, vendor, ""); err != nil {
				log.Printf("scanner: upsert %s: %v", mac, err)
				continue
			}
			updated = true
		case <-readDone:
			// drain any buffered replies before exiting
			for {
				select {
				case pkt := <-replies:
					mac := pkt.SenderHardwareAddr.String()
					ip := pkt.SenderIP.String()
					vendor := LookupVendor(mac)
					if _, err := s.DB.UpsertSeen(mac, ip, vendor, ""); err == nil {
						updated = true
					}
				default:
					if updated && s.OnUpdate != nil {
						s.OnUpdate()
					}
					return nil
				}
			}
		}
	}
}

// pickInterface finds the interface (and its IPv4 network) to scan. If name
// is empty, the first up, non-loopback interface with a private IPv4 address
// is used.
func pickInterface(name string) (*net.Interface, *net.IPNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, ifi := range ifaces {
		if name != "" && ifi.Name != name {
			continue
		}
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue
			}
			ifiCopy := ifi
			return &ifiCopy, &net.IPNet{IP: ip4, Mask: ipnet.Mask}, nil
		}
	}
	if name != "" {
		return nil, nil, fmt.Errorf("interface %q not found or has no IPv4 address", name)
	}
	return nil, nil, fmt.Errorf("no usable network interface found")
}

// hostAddrs enumerates every usable host address in ipnet, excluding the
// network and broadcast addresses, capped to avoid scanning huge ranges.
func hostAddrs(ipnet *net.IPNet) []netip.Addr {
	const maxHosts = 4096

	base, ok := netip.AddrFromSlice(ipnet.IP.To4())
	if !ok {
		return nil
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones >= 31 {
		return []netip.Addr{base} // point-to-point / host route
	}
	hostBits := bits - ones
	total := uint32(1) << uint(hostBits)
	if total > maxHosts {
		total = maxHosts
	}

	netInt := ipToUint32(base.As4())
	networkAddr := netInt &^ (uint32(1)<<uint(hostBits) - 1)
	broadcastAddr := networkAddr | (uint32(1)<<uint(hostBits) - 1)

	out := make([]netip.Addr, 0, total)
	for i := uint32(1); i < total-1; i++ {
		ip := networkAddr + i
		if ip == networkAddr || ip == broadcastAddr {
			continue
		}
		out = append(out, netip.AddrFrom4(uint32ToBytes(ip)))
	}
	return out
}

func ipToUint32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToBytes(v uint32) [4]byte {
	return [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}
