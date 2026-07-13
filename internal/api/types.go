package api

import (
	"time"
)

type PeerView struct {
	URLID               string
	Name                string
	Online              bool
	Disabled            bool
	Endpoint            string
	AllowedIPs          []string
	LastHandshake       time.Time
	RxBytes             uint64
	TxBytes             uint64
	PersistentKeepalive int
	// P12Password is the PKCS#12 import password for cert-based clients
	// (IKEv2); shown so the operator can hand it over with the .p12.
	P12Password string
	// ExpiresAt is set when the peer has a scheduled expiry.
	ExpiresAt time.Time
	// Muted: notifications for this peer are silenced.
	Muted bool
	// Category: "site" or "client" (empty => client).
	Category string
	// OwnerUserID/OwnerUsername: the portal user this peer is assigned to
	// for self-service (0/"" => unassigned).
	OwnerUserID   int64
	OwnerUsername string
	// NodeOwnerID/NodeOwnerName: the equipment node ("Узел") this peer is
	// assigned to, if any (0/"" => unassigned). Mutually exclusive with
	// OwnerUserID -- a peer belongs to at most one of the two owner kinds
	// (enforced in apiPeerSetOwner/apiPeerSetNodeOwner), never both.
	NodeOwnerID   int64
	NodeOwnerName string
}

type notifyChannelView struct {
	Kind    string
	Label   string
	Enabled bool
	Fields  []notifyFieldView
}

type notifyFieldView struct {
	Key    string
	Label  string
	Value  string // non-secret values echoed; secrets shown as "set"/blank
	Secret bool
	Set    bool
}

type notifyView struct {
	Channels []notifyChannelView
	// event + report settings
	EvIfaceUpDown       bool
	EvSiteConnect       bool
	EvSiteDisconnect    bool
	EvClientConnect     bool
	EvClientDisconnect  bool
	EvUnknownPeer       bool
	ReportEnabled       bool
	ReportIntervalHours int
	ReportIncludeEvents bool
	ReportIncludeStatus bool
	CtntProvider        bool
	CtntEndpoint        bool
	CtntAddress         bool
	CtntTime            bool
	PendingCount        int
}
