# HuzLocalNetwork-linux

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-%23FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=000000)](https://www.buymeacoffee.com/khiemtrung)

LAN device monitor with ARP presence discovery, local device control, and
optional identity/service enrichment.

## Discovery behavior

- ARP scans run on the configured interval and are the source of online/offline state.
- Reverse DNS runs in the background every five minutes with a one-second timeout per host.
- UPnP/SSDP discovery runs in the background every 30 minutes to collect a device's friendly name, manufacturer, and model when advertised.
- The **Scan** action probes only a fixed set of common TCP service ports for that selected device. It uses short timeouts and does not run automatically in the ARP loop.

Operate the monitor and use active service scans only on networks and devices you own or are authorized to assess.

## Screenshot

<p align="center">
	<img src="img/screenshot.png" alt="HuzLocalNetwork screenshot" style="max-width:100%;height:auto;" />
</p>
