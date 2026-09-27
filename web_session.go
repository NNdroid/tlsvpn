package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	webSessionCookie = "tlsvpn_session"
	webSessionTTL    = 24 * time.Hour
)

type webSession struct {
	expires  time.Time
	authHash [32]byte
}

type webSessionStore struct {
	mu       sync.Mutex
	sessions map[string]webSession
}

var dashboardSessions = webSessionStore{sessions: make(map[string]webSession)}

func webAuthHash(auth string) [32]byte { return sha256.Sum256([]byte(auth)) }

func (s *webSessionStore) create(auth string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	now := time.Now()
	s.mu.Lock()
	for k, v := range s.sessions {
		if now.After(v.expires) {
			delete(s.sessions, k)
		}
	}
	s.sessions[token] = webSession{expires: now.Add(webSessionTTL), authHash: webAuthHash(auth)}
	s.mu.Unlock()
	return token, nil
}

func (s *webSessionStore) valid(token, auth string) bool {
	if token == "" || auth == "" {
		return false
	}
	now := time.Now()
	h := webAuthHash(auth)
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.sessions[token]
	if !ok || now.After(v.expires) || subtle.ConstantTimeCompare(v.authHash[:], h[:]) != 1 {
		if ok {
			delete(s.sessions, token)
		}
		return false
	}
	// Sliding expiry keeps an actively used dashboard signed in while still
	// bounding abandoned sessions. Changing web.auth invalidates it immediately
	// because the stored auth hash no longer matches.
	v.expires = now.Add(webSessionTTL)
	s.sessions[token] = v
	return true
}

func (s *webSessionStore) revoke(token string) {
	if token == "" {
		return
	}
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

func dashboardSessionToken(r *http.Request) string {
	c, err := r.Cookie(webSessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

func setDashboardSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	https := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name: webSessionCookie, Value: token, Path: "/", MaxAge: int(webSessionTTL.Seconds()),
		HttpOnly: true, Secure: https, SameSite: http.SameSiteLaxMode,
	})
}

func clearDashboardSessionCookie(w http.ResponseWriter, r *http.Request) {
	https := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name: webSessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: https, SameSite: http.SameSiteLaxMode,
	})
}

func handleDashboardLogin(w http.ResponseWriter, r *http.Request, expected string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if expected == "" || !constantTimeCredentialEqual(req.Username+":"+req.Password, expected) {
		time.Sleep(150 * time.Millisecond)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	token, err := dashboardSessions.create(expected)
	if err != nil {
		http.Error(w, "Unable to create session", http.StatusInternalServerError)
		return
	}
	setDashboardSessionCookie(w, r, token)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func handleDashboardLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dashboardSessions.revoke(dashboardSessionToken(r))
	clearDashboardSessionCookie(w, r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
