// Package zabbix embeds the ready-to-import Zabbix template files (see
// README.md in this directory) so the panel can serve them for download
// directly from the admin UI -- this panel is meant to be operated entirely
// through its own interface, never by pulling files off the host/repo by hand.
package zabbix

import "embed"

//go:embed protean-zabbix-7.4.yaml protean-zabbix-8.0.yaml
var FS embed.FS
