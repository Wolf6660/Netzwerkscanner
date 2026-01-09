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

<h2>Docker</h2>
- git clone https://github.com/DEINNAME/netscan-web.git
- cd netscan-web

<h2>Synology (Container Manager)</h2>
- Repo/Ordner auf die Synology kopieren (z.B. /volume1/docker/netscan-web)
  (auf den grünen Button code klicken und auf Download zip) 
- Container Manager → Projekt → Erstellen → Ordner auswählen und die abfrage ob docker-compose.yml genutz werden soll bestätigen
- Projekt starten
- http://<synology>:22222 öffnen (ist in der docker-compose.yml anpassbar)

Ports / VPN Tipps
Für VPN meist besser: TCP-Ping aktivieren (Ports z.B. 22,80,443,445,3389)
Reverse DNS nur aktivieren, wenn PTR Records sauber gepflegt sind

Datenhaltung
SQLite liegt in ./data/netscan.sqlite3
Dieser Ordner ist per .gitignore von Git ausgeschlossen
