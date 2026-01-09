# Netzwerkscanner

Kleine Weboberfläche (Docker/Synology-tauglich), um per Klick IP-Bereiche (auch über Site-to-Site VPN) zu scannen
und Geräte als **Up/Down** inkl. Hostname anzuzeigen. Zusätzlich können pro IP **Alias-Namen** gespeichert werden,
die beim nächsten Scan wieder erscheinen. Preset-Buttons lassen sich im UI konfigurieren.

- Preset-Buttons für IP-Bereiche (Name + Range)
- Manuelle Eingabe: `CIDR` (z.B. `10.10.0.0/24`) oder `Start-Ende` (z.B. `10.10.0.10-10.10.0.50`)
- Scan via `nmap -sn` (optional TCP-Ping auf Ports für VPN-Umgebungen)
- Reverse DNS optional
- Alias-Namen + Notizen pro IP (SQLite persistent)
- Einstellungsseite zum Verwalten der Presets


Synology (Container Manager)
- Repo/Ordner auf die Synology kopieren (z.B. /volume1/docker/netscan-web)
- Container Manager → Projekt → Erstellen → docker-compose.yml auswählen
- Projekt starten
- http://<synology>:22222 öffnen

Ports / VPN Tipps
Für VPN meist besser: TCP-Ping aktivieren (Ports z.B. 22,80,443,445,3389)
Reverse DNS nur aktivieren, wenn PTR Records sauber gepflegt sind

Datenhaltung
SQLite liegt in ./data/netscan.sqlite3
Dieser Ordner ist per .gitignore von Git ausgeschlossen
