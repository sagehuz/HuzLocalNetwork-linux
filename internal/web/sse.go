package web

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Hub fans out Server-Sent Events to connected dashboard clients.
type Hub struct {
	mu      sync.Mutex
	clients map[chan string]struct{}
}

// NewHub creates an empty SSE hub.
func NewHub() *Hub {
	return &Hub{clients: make(map[chan string]struct{})}
}

// Broadcast sends event to every currently connected client. Non-blocking:
// slow/stuck clients are skipped rather than stalling the broadcaster.
func (h *Hub) Broadcast(event string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- event:
		default:
		}
	}
}

// NotifyDevicesChanged is a convenience callback wired into the scanner and
// spoofer so they can trigger a UI refresh.
func (h *Hub) NotifyDevicesChanged() {
	h.Broadcast("devices-changed")
}

// ServeHTTP implements the /events SSE endpoint.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan string, 8)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.clients, ch)
		h.mu.Unlock()
		close(ch)
	}()

	// Initial nudge so the client renders the current state right away.
	fmt.Fprintf(w, "event: devices-changed\ndata: connected\n\n")
	flusher.Flush()

	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-ch:
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", msg, msg)
			flusher.Flush()
		case <-keepalive.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
