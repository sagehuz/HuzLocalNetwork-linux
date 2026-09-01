// Command server is the entry point for the LAN Monitor & Device Control
// dashboard: it opens the device database, starts the background ARP
// scanner, and serves the embedded web dashboard.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"lanmonitor/internal/db"
	"lanmonitor/internal/scanner"
	"lanmonitor/internal/spoofer"
	"lanmonitor/internal/web"
)

func main() {
	var (
		addr         = flag.String("addr", ":8080", "HTTP listen address")
		dbPath       = flag.String("db", "lanmonitor.db", "path to the SQLite database file")
		ifaceName    = flag.String("iface", "", "network interface to scan (auto-detected if empty)")
		gatewayFlag  = flag.String("gateway", "", "LAN gateway IPv4 address (auto-detected from /proc/net/route if empty)")
		scanInterval = flag.Duration("scan-interval", 30*time.Second, "how often to run a full ARP sweep")
	)
	flag.Parse()

	database, err := db.Open(*dbPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer database.Close()

	sc, err := scanner.New(database, *ifaceName, *scanInterval)
	if err != nil {
		log.Fatalf("init scanner: %v", err)
	}

	gatewayStr := *gatewayFlag
	if gatewayStr == "" {
		gatewayStr, err = defaultGatewayIPv4()
		if err != nil {
			log.Fatalf("detect default gateway (pass -gateway to override): %v", err)
		}
	}
	gatewayIP, err := netip.ParseAddr(gatewayStr)
	if err != nil {
		log.Fatalf("invalid gateway address %q: %v", gatewayStr, err)
	}
	log.Printf("using gateway %s", gatewayIP)

	spf := spoofer.New(sc.Iface, gatewayIP)

	hub := web.NewHub()
	sc.OnUpdate = hub.NotifyDevicesChanged
	discovery := scanner.NewDiscovery(database)
	discovery.OnUpdate = hub.NotifyDevicesChanged

	srv := &web.Server{DB: database, Hub: hub, Spoofer: spf, Discovery: discovery}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go sc.Run(ctx)
	go discovery.Run(ctx)

	httpServer := &http.Server{Addr: *addr, Handler: srv.Routes()}
	go func() {
		log.Printf("listening on %s", *addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down…")
	spf.StopAll()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("http shutdown: %v", err)
	}
}

// defaultGatewayIPv4 reads the kernel routing table to find the default
// (0.0.0.0/0) IPv4 gateway. Linux-specific (/proc/net/route).
func defaultGatewayIPv4() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", fmt.Errorf("open /proc/net/route: %w", err)
	}
	defer f.Close()

	scan := bufio.NewScanner(f)
	scan.Scan() // header line
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) < 3 {
			continue
		}
		destHex, gatewayHex := fields[1], fields[2]
		if destHex != "00000000" {
			continue // not the default route
		}
		ip, err := hexLittleEndianToIPv4(gatewayHex)
		if err != nil {
			return "", err
		}
		return ip, nil
	}
	if err := scan.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no default route found in /proc/net/route")
}

// hexLittleEndianToIPv4 converts the little-endian hex gateway field from
// /proc/net/route (e.g. "0101A8C0") into dotted-decimal form.
func hexLittleEndianToIPv4(hexLE string) (string, error) {
	v, err := strconv.ParseUint(hexLE, 16, 32)
	if err != nil {
		return "", fmt.Errorf("parse route hex %q: %w", hexLE, err)
	}
	b := [4]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]), nil
}
