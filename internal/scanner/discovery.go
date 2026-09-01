package scanner

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"lanmonitor/internal/db"
)

const (
	identityInterval = 5 * time.Minute
	ssdpInterval     = 30 * time.Minute
)

var commonServices = []struct {
	port int
	name string
}{
	{22, "SSH"}, {53, "DNS"}, {80, "HTTP"}, {443, "HTTPS"}, {445, "SMB"},
	{554, "RTSP"}, {631, "IPP"}, {1883, "MQTT"}, {8008, "Cast"},
	{8080, "HTTP-alt"}, {8443, "HTTPS-alt"}, {9100, "Printer"},
}

// Discovery enriches known ARP hosts without delaying the ARP presence sweep.
type Discovery struct {
	DB       *db.DB
	OnUpdate func()

	serviceScan sync.Mutex
}

// NewDiscovery creates a background discovery worker for known devices.
func NewDiscovery(database *db.DB) *Discovery {
	return &Discovery{DB: database}
}

// Run performs low-frequency reverse DNS and SSDP discovery until ctx ends.
func (d *Discovery) Run(ctx context.Context) {
	initialDelay := time.NewTimer(5 * time.Second)
	defer initialDelay.Stop()
	select {
	case <-ctx.Done():
		return
	case <-initialDelay.C:
	}
	d.refreshIdentity(ctx)
	d.discoverSSDP(ctx)

	identityTicker := time.NewTicker(identityInterval)
	ssdpTicker := time.NewTicker(ssdpInterval)
	defer identityTicker.Stop()
	defer ssdpTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-identityTicker.C:
			d.refreshIdentity(ctx)
		case <-ssdpTicker.C:
			d.discoverSSDP(ctx)
		}
	}
}

func (d *Discovery) refreshIdentity(ctx context.Context) {
	devices, err := d.DB.All()
	if err != nil {
		return
	}
	changed := false
	for _, device := range devices {
		if device.IP == "" || device.Hostname != "" {
			continue
		}
		lookupCtx, cancel := context.WithTimeout(ctx, time.Second)
		names, err := net.DefaultResolver.LookupAddr(lookupCtx, device.IP)
		cancel()
		if err != nil || len(names) == 0 {
			continue
		}
		hostname := strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
		if hostname != "" && d.DB.UpdateEnrichment(device.MAC, hostname, "", "", "") == nil {
			changed = true
		}
	}
	if changed && d.OnUpdate != nil {
		d.OnUpdate()
	}
}

// ScanServices probes a small, fixed TCP port set for a single known device.
func (d *Discovery) ScanServices(ctx context.Context, device db.Device) error {
	if device.IP == "" {
		return fmt.Errorf("device has no known IP address")
	}
	d.serviceScan.Lock()
	defer d.serviceScan.Unlock()

	var wg sync.WaitGroup
	results := make(chan string, len(commonServices))
	limiter := make(chan struct{}, 4)
	for _, service := range commonServices {
		wg.Add(1)
		go func(port int, name string) {
			defer wg.Done()
			select {
			case limiter <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-limiter }()
			dialer := net.Dialer{Timeout: 750 * time.Millisecond}
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(device.IP, fmt.Sprint(port)))
			if err == nil {
				conn.Close()
				results <- fmt.Sprintf("%s:%d", name, port)
			}
		}(service.port, service.name)
	}
	wg.Wait()
	close(results)

	services := make([]string, 0, len(commonServices))
	for service := range results {
		services = append(services, service)
	}
	sort.Strings(services)
	if err := d.DB.UpdateServices(device.MAC, strings.Join(services, ", ")); err != nil {
		return err
	}
	if d.OnUpdate != nil {
		d.OnUpdate()
	}
	return nil
}

func (d *Discovery) discoverSSDP(ctx context.Context) {
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return
	}
	defer conn.Close()

	request := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
	if _, err := conn.WriteToUDP([]byte(request), &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 1900}); err != nil {
		return
	}
	deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	changed := false
	for {
		if err := conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			return
		}
		buffer := make([]byte, 4096)
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if deadline.Err() != nil {
				break
			}
			continue
		}
		if d.storeSSDP(ctx, addr.IP.String(), string(buffer[:n])) {
			changed = true
		}
	}
	if changed && d.OnUpdate != nil {
		d.OnUpdate()
	}
}

type upnpDescription struct {
	Device struct {
		FriendlyName string `xml:"friendlyName"`
		Manufacturer string `xml:"manufacturer"`
		ModelName    string `xml:"modelName"`
		DeviceType   string `xml:"deviceType"`
	} `xml:"device"`
}

func (d *Discovery) storeSSDP(ctx context.Context, ip, response string) bool {
	location := ""
	for _, line := range strings.Split(response, "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && strings.EqualFold(name, "location") {
			location = strings.TrimSpace(value)
			break
		}
	}
	if location == "" {
		return false
	}
	requestCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, location, nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	var description upnpDescription
	if xml.NewDecoder(resp.Body).Decode(&description) != nil {
		return false
	}
	devices, err := d.DB.All()
	if err != nil {
		return false
	}
	for _, device := range devices {
		if device.IP == ip {
			typeName := inferDeviceType(description.Device.DeviceType, description.Device.ModelName)
			return d.DB.UpdateEnrichment(device.MAC, description.Device.FriendlyName, typeName, description.Device.Manufacturer, description.Device.ModelName) == nil
		}
	}
	return false
}

func inferDeviceType(deviceType, model string) string {
	text := strings.ToLower(deviceType + " " + model)
	switch {
	case strings.Contains(text, "printer"):
		return "Printer"
	case strings.Contains(text, "media") || strings.Contains(text, "tv") || strings.Contains(text, "renderer"):
		return "Media device"
	case strings.Contains(text, "router") || strings.Contains(text, "gateway"):
		return "Router"
	case strings.Contains(text, "camera"):
		return "Camera"
	default:
		return ""
	}
}
