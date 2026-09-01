// Vanilla JS dashboard: fetches the device list and stays in sync via SSE.
// (No external UI framework is bundled, so the whole frontend is embedded
// into the Go binary via //go:embed with zero runtime dependencies.)

const tbody = document.getElementById("devices-body");
const statusPill = document.getElementById("conn-status");

function escapeHTML(str) {
	const div = document.createElement("div");
	div.textContent = str ?? "";
	return div.innerHTML;
}

function timeAgo(iso) {
	const then = new Date(iso).getTime();
	if (Number.isNaN(then)) return "-";
	const diff = Math.max(0, Date.now() - then);
	const s = Math.floor(diff / 1000);
	if (s < 60) return `${s}s trước`;
	const m = Math.floor(s / 60);
	if (m < 60) return `${m}p trước`;
	const h = Math.floor(m / 60);
	return `${h}h trước`;
}

function timeSince(iso) {
	const then = new Date(iso).getTime();
	if (Number.isNaN(then)) return "-";
	const minutes = Math.max(0, Math.floor((Date.now() - then) / 60000));
	if (minutes < 60) return `${minutes}p`;
	const hours = Math.floor(minutes / 60);
	if (hours < 24) return `${hours}h`;
	return `${Math.floor(hours / 24)}d`;
}

function renderRow(dev) {
	const isOnline = dev.status === "online";
	const displayName = dev.alias || dev.hostname || "-";
	const actionLabel = dev.blocked ? "Reconnect" : "Disconnect";
	const actionClass = dev.blocked ? "action blocked" : "action";
	const blockedBadge = dev.blocked ? '<span class="blocked-badge">BLOCKED</span>' : "";

	return `
		<tr data-mac="${escapeHTML(dev.mac)}">
			<td><span class="dot ${isOnline ? "dot-online" : "dot-offline"}"></span>${isOnline ? "Online" : "Offline"}</td>
			<td class="mono">${escapeHTML(dev.ip)}</td>
			<td class="mono">${escapeHTML(dev.mac)}</td>
			<td>${escapeHTML(dev.vendor) || "-"}</td>
			<td>
				<input class="alias-input" type="text" value="${escapeHTML(dev.alias)}" placeholder="${escapeHTML(dev.hostname) || "name it..."}" data-mac="${escapeHTML(dev.mac)}">
				${dev.hostname ? `<small class="discovered-name" title="${escapeHTML(dev.hostname)}">${escapeHTML(dev.hostname)}</small>` : ""}
				${blockedBadge}
			</td>
			<td>${escapeHTML(dev.device_type) || "-"}</td>
			<td class="truncate" title="${escapeHTML([dev.manufacturer, dev.model].filter(Boolean).join(" "))}">${escapeHTML([dev.manufacturer, dev.model].filter(Boolean).join(" ")) || "-"}</td>
			<td class="services-cell" title="${escapeHTML(dev.services)}">${escapeHTML(dev.services) || "-"}<button class="service-scan" title="Scan common service ports" data-mac="${escapeHTML(dev.mac)}">Scan</button></td>
			<td title="${escapeHTML(dev.first_seen)}">${timeSince(dev.first_seen)}</td>
			<td>${timeAgo(dev.last_seen)}</td>
			<td><button class="${actionClass}" data-mac="${escapeHTML(dev.mac)}" data-blocked="${dev.blocked}">${actionLabel}</button></td>
		</tr>`;
}

async function refreshDevices() {
	try {
		const res = await fetch("/api/devices");
		if (!res.ok) throw new Error(`HTTP ${res.status}`);
		const devices = await res.json();
		if (!devices || devices.length === 0) {
			tbody.innerHTML = `<tr><td colspan="11" class="empty">No devices detected.</td></tr>`;
			return;
		}
		tbody.innerHTML = devices.map(renderRow).join("");
	} catch (err) {
		console.error("refreshDevices failed", err);
	}
}

tbody.addEventListener("click", async (e) => {
	const scanButton = e.target.closest("button.service-scan");
	if (scanButton) {
		scanButton.disabled = true;
		try {
			const res = await fetch(`/api/devices/${encodeURIComponent(scanButton.dataset.mac)}/services/scan`, { method: "POST" });
			if (!res.ok) throw new Error(await res.text());
			setTimeout(refreshDevices, 3000);
		} catch (err) {
			alert(`Unable to scan services: ${err.message}`);
			scanButton.disabled = false;
		}
		return;
	}
	const btn = e.target.closest("button.action");
	if (!btn) return;
	const mac = btn.dataset.mac;
	const isBlocked = btn.dataset.blocked === "true";
	const endpoint = isBlocked ? "reconnect" : "disconnect";
	btn.disabled = true;
	try {
		const res = await fetch(`/api/devices/${encodeURIComponent(mac)}/${endpoint}`, { method: "POST" });
		if (!res.ok) throw new Error(await res.text());
		await refreshDevices();
	} catch (err) {
		alert(`Unable to ${endpoint} device: ${err.message}`);
		btn.disabled = false;
	}
});

let aliasTimer = null;
tbody.addEventListener("input", (e) => {
	const input = e.target.closest("input.alias-input");
	if (!input) return;
	clearTimeout(aliasTimer);
	const mac = input.dataset.mac;
	const alias = input.value;
	aliasTimer = setTimeout(async () => {
		try {
			await fetch(`/api/devices/${encodeURIComponent(mac)}/alias`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ alias }),
			});
		} catch (err) {
			console.error("save alias failed", err);
		}
	}, 500);
});

function connectSSE() {
	const es = new EventSource("/events");
	es.addEventListener("devices-changed", () => refreshDevices());
	es.onopen = () => {
		statusPill.textContent = "live";
		statusPill.className = "status-pill status-online";
	};
	es.onerror = () => {
		statusPill.textContent = "reconnecting…";
		statusPill.className = "status-pill status-offline";
	};
}

refreshDevices();
connectSSE();
setInterval(refreshDevices, 30000); // safety-net poll in case an SSE event is missed
