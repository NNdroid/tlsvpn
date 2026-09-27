package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func restartTestToken(ch string) string { return strings.Repeat(ch, 64) }

func TestPersistSessionStateAcceptsEpochResetForNewSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.state")
	old := &clientState{
		ClientID:     "client-a",
		MAC:          "02:00:00:00:00:02",
		SessionID:    "old-session",
		SessionToken: restartTestToken("a"),
		SessionEpoch: 42,
	}
	if err := saveClientState(path, old); err != nil {
		t.Fatal(err)
	}

	newToken := restartTestToken("b")
	c := &Client{
		clientID:        "client-a",
		stateFile:       path,
		state:           old,
		serverSessionID: "new-session",
		sessionToken:    newToken,
		sessionEpoch:    1,
	}
	c.persistSessionState("new-session", newToken, 1)

	got, err := loadClientState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID != "new-session" || got.SessionEpoch != 1 || got.SessionToken != newToken {
		t.Fatalf("new server session was not persisted: %+v", got)
	}
	if got.MAC != old.MAC {
		t.Fatalf("stable MAC was lost while replacing session state: got %q want %q", got.MAC, old.MAC)
	}
}

func TestPersistSessionStateRejectsLateResponseFromOldSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.state")
	newToken := restartTestToken("c")
	current := &clientState{
		ClientID:     "client-a",
		MAC:          "02:00:00:00:00:02",
		SessionID:    "new-session",
		SessionToken: newToken,
		SessionEpoch: 2,
	}
	if err := saveClientState(path, current); err != nil {
		t.Fatal(err)
	}
	c := &Client{
		clientID:        "client-a",
		stateFile:       path,
		state:           current,
		serverSessionID: "new-session",
		sessionToken:    newToken,
		sessionEpoch:    2,
	}

	c.persistSessionState("old-session", restartTestToken("d"), 99)
	got, err := loadClientState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID != "new-session" || got.SessionToken != newToken || got.SessionEpoch != 2 {
		t.Fatalf("late old-session response rolled state back: %+v", got)
	}
}

func TestRefreshSessionStateFromDiskAdoptsNewerSameSessionToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.state")
	oldToken := restartTestToken("e")
	newToken := restartTestToken("f")
	disk := &clientState{
		ClientID:     "client-a",
		MAC:          "02:00:00:00:00:02",
		SessionID:    "same-session",
		SessionToken: newToken,
		SessionEpoch: 8,
	}
	if err := saveClientState(path, disk); err != nil {
		t.Fatal(err)
	}
	c := &Client{
		clientID:        "client-a",
		stateFile:       path,
		state:           &clientState{ClientID: "client-a", SessionID: "same-session", SessionToken: oldToken, SessionEpoch: 7},
		serverSessionID: "same-session",
		sessionToken:    oldToken,
		sessionEpoch:    7,
	}

	c.refreshSessionStateFromDisk()
	if c.sessionEpoch != 8 || c.sessionToken != newToken || c.serverSessionID != "same-session" {
		t.Fatalf("did not adopt newer persisted token: id=%q epoch=%d token=%q", c.serverSessionID, c.sessionEpoch, c.sessionToken)
	}
}

func TestRefreshSessionStateFromDiskDoesNotSwitchSessionID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.state")
	disk := &clientState{
		ClientID:     "client-a",
		SessionID:    "other-session",
		SessionToken: restartTestToken("1"),
		SessionEpoch: 100,
	}
	if err := saveClientState(path, disk); err != nil {
		t.Fatal(err)
	}
	currentToken := restartTestToken("2")
	c := &Client{
		clientID:        "client-a",
		stateFile:       path,
		serverSessionID: "current-session",
		sessionToken:    currentToken,
		sessionEpoch:    3,
	}

	c.refreshSessionStateFromDisk()
	if c.serverSessionID != "current-session" || c.sessionEpoch != 3 || c.sessionToken != currentToken {
		t.Fatalf("unrelated persisted session replaced live in-memory identity: id=%q epoch=%d", c.serverSessionID, c.sessionEpoch)
	}
}
