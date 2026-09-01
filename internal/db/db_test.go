package db

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestOpenMigratesExistingDevicesTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.db")
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Exec(`
		CREATE TABLE devices (
			mac TEXT PRIMARY KEY, ip TEXT NOT NULL DEFAULT '', vendor TEXT NOT NULL DEFAULT '',
			hostname TEXT NOT NULL DEFAULT '', alias TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'offline', blocked INTEGER NOT NULL DEFAULT 0,
			first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL
		);
		INSERT INTO devices (mac, first_seen, last_seen) VALUES ('aa:bb:cc:dd:ee:ff', ?, ?);`, time.Now(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	database, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	devices, err := database.All()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected one device, got %d", len(devices))
	}
	if devices[0].LastEnriched != nil || devices[0].LastServicesScanned != nil {
		t.Fatal("expected optional enrichment timestamps to be nil")
	}
}
