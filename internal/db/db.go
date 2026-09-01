// Package db manages the SQLite-backed device inventory and scan history.
package db

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Device represents a single LAN host tracked by the monitor.
type Device struct {
	MAC                 string     `json:"mac"`
	IP                  string     `json:"ip"`
	Vendor              string     `json:"vendor"`
	Hostname            string     `json:"hostname"`
	DeviceType          string     `json:"device_type"`
	Manufacturer        string     `json:"manufacturer"`
	Model               string     `json:"model"`
	Services            string     `json:"services"`
	LastEnriched        *time.Time `json:"last_enriched"`
	LastServicesScanned *time.Time `json:"last_services_scanned"`
	Alias               string     `json:"alias"`
	Status              string     `json:"status"` // "online" | "offline"
	Blocked             bool       `json:"blocked"`
	FirstSeen           time.Time  `json:"first_seen"`
	LastSeen            time.Time  `json:"last_seen"`
}

// DB wraps the underlying sql.DB with the schema used by the application.
type DB struct {
	conn *sql.DB
}

// Open initializes (or migrates) the SQLite database at path.
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	conn.SetMaxOpenConns(1) // modernc.org/sqlite: serialize writes to avoid "database is locked"

	if _, err := conn.Exec(schema); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}
	if err := migrateDevices(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate device fields: %w", err)
	}
	return &DB{conn: conn}, nil
}

// Close releases the underlying database connection.
func (d *DB) Close() error {
	return d.conn.Close()
}

const schema = `
CREATE TABLE IF NOT EXISTS devices (
	mac        TEXT PRIMARY KEY,
	ip         TEXT NOT NULL DEFAULT '',
	vendor     TEXT NOT NULL DEFAULT '',
	hostname   TEXT NOT NULL DEFAULT '',
	device_type TEXT NOT NULL DEFAULT '',
	manufacturer TEXT NOT NULL DEFAULT '',
	model      TEXT NOT NULL DEFAULT '',
	services   TEXT NOT NULL DEFAULT '',
	last_enriched DATETIME,
	last_services_scanned DATETIME,
	alias      TEXT NOT NULL DEFAULT '',
	status     TEXT NOT NULL DEFAULT 'offline',
	blocked    INTEGER NOT NULL DEFAULT 0,
	first_seen DATETIME NOT NULL,
	last_seen  DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS history (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	mac       TEXT NOT NULL,
	event     TEXT NOT NULL,
	at        DATETIME NOT NULL
);
`

func migrateDevices(conn *sql.DB) error {
	columns := []string{
		"device_type TEXT NOT NULL DEFAULT ''",
		"manufacturer TEXT NOT NULL DEFAULT ''",
		"model TEXT NOT NULL DEFAULT ''",
		"services TEXT NOT NULL DEFAULT ''",
		"last_enriched DATETIME",
		"last_services_scanned DATETIME",
	}
	for _, column := range columns {
		if _, err := conn.Exec("ALTER TABLE devices ADD COLUMN " + column); err != nil {
			if !strings.Contains(err.Error(), "duplicate column name") {
				return err
			}
		}
	}
	return nil
}

// UpsertSeen records that a device replied to a scan, creating it if new.
func (d *DB) UpsertSeen(mac, ip, vendor, hostname string) (isNew bool, err error) {
	now := time.Now().UTC()

	res, err := d.conn.Exec(`
		UPDATE devices
		SET ip = ?, vendor = CASE WHEN vendor = '' THEN ? ELSE vendor END,
		    hostname = CASE WHEN ? != '' THEN ? ELSE hostname END,
		    status = 'online', last_seen = ?
		WHERE mac = ?`,
		ip, vendor, hostname, hostname, now, mac)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return false, nil
	}

	_, err = d.conn.Exec(`
		INSERT INTO devices (mac, ip, vendor, hostname, alias, status, blocked, first_seen, last_seen)
		VALUES (?, ?, ?, ?, '', 'online', 0, ?, ?)`,
		mac, ip, vendor, hostname, now, now)
	if err != nil {
		return false, err
	}
	d.addHistory(mac, "new_device")
	return true, nil
}

// MarkOfflineStaleSince flips devices not seen since `since` to offline and
// returns the MAC addresses that changed state.
func (d *DB) MarkOfflineStaleSince(since time.Time) ([]string, error) {
	rows, err := d.conn.Query(`SELECT mac FROM devices WHERE status = 'online' AND last_seen < ?`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var changed []string
	for rows.Next() {
		var mac string
		if err := rows.Scan(&mac); err != nil {
			return nil, err
		}
		changed = append(changed, mac)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(changed) == 0 {
		return nil, nil
	}
	if _, err := d.conn.Exec(`UPDATE devices SET status = 'offline' WHERE status = 'online' AND last_seen < ?`, since); err != nil {
		return nil, err
	}
	for _, mac := range changed {
		d.addHistory(mac, "offline")
	}
	return changed, nil
}

// SetAlias updates the human-friendly name for a device.
func (d *DB) SetAlias(mac, alias string) error {
	_, err := d.conn.Exec(`UPDATE devices SET alias = ? WHERE mac = ?`, alias, mac)
	return err
}

// SetBlocked persists the block/spoof state for a device.
func (d *DB) SetBlocked(mac string, blocked bool) error {
	_, err := d.conn.Exec(`UPDATE devices SET blocked = ? WHERE mac = ?`, blocked, mac)
	if err == nil {
		evt := "unblocked"
		if blocked {
			evt = "blocked"
		}
		d.addHistory(mac, evt)
	}
	return err
}

// UpdateEnrichment stores identity metadata learned outside the ARP sweep.
func (d *DB) UpdateEnrichment(mac, hostname, deviceType, manufacturer, model string) error {
	_, err := d.conn.Exec(`
		UPDATE devices
		SET hostname = CASE WHEN ? != '' THEN ? ELSE hostname END,
		    device_type = CASE WHEN ? != '' THEN ? ELSE device_type END,
		    manufacturer = CASE WHEN ? != '' THEN ? ELSE manufacturer END,
		    model = CASE WHEN ? != '' THEN ? ELSE model END,
		    last_enriched = ?
		WHERE mac = ?`,
		hostname, hostname, deviceType, deviceType, manufacturer, manufacturer, model, model,
		time.Now().UTC(), mac)
	return err
}

// UpdateServices stores the cached result of a bounded service scan.
func (d *DB) UpdateServices(mac, services string) error {
	_, err := d.conn.Exec(`
		UPDATE devices SET services = ?, last_services_scanned = ? WHERE mac = ?`,
		services, time.Now().UTC(), mac)
	return err
}

// Get returns a single device by MAC address.
func (d *DB) Get(mac string) (Device, error) {
	var dev Device
	var blocked int
	err := d.conn.QueryRow(`
		SELECT mac, ip, vendor, hostname, device_type, manufacturer, model, services,
		       last_enriched, last_services_scanned, alias, status, blocked, first_seen, last_seen
		FROM devices WHERE mac = ?`, mac).
		Scan(&dev.MAC, &dev.IP, &dev.Vendor, &dev.Hostname, &dev.DeviceType, &dev.Manufacturer,
			&dev.Model, &dev.Services, &dev.LastEnriched, &dev.LastServicesScanned, &dev.Alias,
			&dev.Status, &blocked, &dev.FirstSeen, &dev.LastSeen)
	dev.Blocked = blocked != 0
	return dev, err
}

// All returns every known device ordered by IP address.
func (d *DB) All() ([]Device, error) {
	rows, err := d.conn.Query(`
		SELECT mac, ip, vendor, hostname, device_type, manufacturer, model, services,
		       last_enriched, last_services_scanned, alias, status, blocked, first_seen, last_seen
		FROM devices ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		var dev Device
		var blocked int
		if err := rows.Scan(&dev.MAC, &dev.IP, &dev.Vendor, &dev.Hostname, &dev.DeviceType, &dev.Manufacturer,
			&dev.Model, &dev.Services, &dev.LastEnriched, &dev.LastServicesScanned, &dev.Alias,
			&dev.Status, &blocked, &dev.FirstSeen, &dev.LastSeen); err != nil {
			return nil, err
		}
		dev.Blocked = blocked != 0
		out = append(out, dev)
	}
	return out, rows.Err()
}

func (d *DB) addHistory(mac, event string) {
	_, _ = d.conn.Exec(`INSERT INTO history (mac, event, at) VALUES (?, ?, ?)`, mac, event, time.Now().UTC())
}
