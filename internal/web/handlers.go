// Package web exposes the HTTP dashboard: JSON API, SSE stream, and the
// embedded static frontend assets.
package web

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"lanmonitor/internal/db"
	"lanmonitor/internal/spoofer"
)

//go:embed static/*
var staticFS embed.FS

// Server wires the database, SSE hub and spoofer together behind an
// http.Handler.
type Server struct {
	DB      *db.DB
	Hub     *Hub
	Spoofer *spoofer.Spoofer
}

// Routes builds the full HTTP handler for the dashboard.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("web: embed static fs: %v", err)
	}
	fileServer := http.FileServer(http.FS(staticSub))

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "/index.html"
		fileServer.ServeHTTP(w, r)
	})
	mux.Handle("GET /static/", http.StripPrefix("/static/", fileServer))

	mux.HandleFunc("GET /events", s.Hub.ServeHTTP)

	mux.HandleFunc("GET /api/devices", s.handleListDevices)
	mux.HandleFunc("POST /api/devices/{mac}/alias", s.handleSetAlias)
	mux.HandleFunc("POST /api/devices/{mac}/disconnect", s.handleDisconnect)
	mux.HandleFunc("POST /api/devices/{mac}/reconnect", s.handleReconnect)

	return mux
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.DB.All()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, devices)
}

func (s *Server) handleSetAlias(w http.ResponseWriter, r *http.Request) {
	mac := normalizeMAC(r.PathValue("mac"))
	var body struct {
		Alias string `json:"alias"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if err := s.DB.SetAlias(mac, strings.TrimSpace(body.Alias)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.Hub.NotifyDevicesChanged()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	mac := normalizeMAC(r.PathValue("mac"))
	dev, err := s.DB.Get(mac)
	if err != nil {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	if dev.IP == "" {
		http.Error(w, "device has no known IP address", http.StatusConflict)
		return
	}
	if err := s.Spoofer.Block(dev.IP); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.DB.SetBlocked(mac, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.Hub.NotifyDevicesChanged()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleReconnect(w http.ResponseWriter, r *http.Request) {
	mac := normalizeMAC(r.PathValue("mac"))
	dev, err := s.DB.Get(mac)
	if err != nil {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	if err := s.Spoofer.Unblock(dev.IP); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.DB.SetBlocked(mac, false); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.Hub.NotifyDevicesChanged()
	w.WriteHeader(http.StatusNoContent)
}

func normalizeMAC(mac string) string {
	return strings.ToLower(strings.TrimSpace(mac))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("web: write json: %v", err)
	}
}
