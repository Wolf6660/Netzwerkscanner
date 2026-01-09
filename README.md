Netzwerkscanner
Kleine Weboberfläche (Docker- und Synology-tauglich), mit der sich per Klick IP-Bereiche – auch über Site-to-Site-VPN – scannen lassen. Gefundene Geräte werden inklusive Hostname als Up/Down angezeigt.

Zusätzlich können pro IP Alias-Namen und Notizen gespeichert werden, die bei späteren Scans automatisch wieder erscheinen.
Über die Oberfläche lassen sich frei konfigurierbare Preset-Buttons für häufig genutzte IP-Bereiche anlegen.

<h2>Funktionen</h2>
- Preset-Buttons für IP-Bereiche (Name + Range)
- Manuelle Eingabe von IP-Bereichen:
   - CIDR (z. B. 10.10.0.0/24)
   - Start–Ende (z. B. 10.10.0.10-10.10.0.50)
- Scan via nmap -sn
- Optionaler TCP-Ping auf definierte Ports (empfohlen für VPN-Umgebungen)
   - Optionales Reverse DNS
- Alias-Namen und Notizen pro IP (persistent in SQLite)
- Eigene Einstellungsseite zum Verwalten der Presets

<h2>Docker</h2>
Repository klonen
<code>git clone https://github.com/Wolf6660/Netzwerkscanner.git</code>
In das Projektverzeichnis wechseln
<code>cd Netzwerkscanner</code>
Optional: Port oder andere Einstellungen anpassen
<code>nano docker-compose.yml</code>
Container bauen und starten
<code>docker compose up -d --build</code>
Weboberfläche aufrufen
<code>http://<IP-oder-Hostname-des-Servers>:22222</code>

<h2>Synology (Container Manager)</h2>
- Repository/Ordner auf die Synology kopieren
   z. B. nach /volume1/docker/netscan-web
  (GitHub → grüner Code-Button → Download ZIP)
- Container Manager → Projekt → Erstellen
- Ordner auswählen und die Abfrage zur Nutzung der docker-compose.yml bestätigen
- Projekt starten
- Weboberfläche öffnen
<code>http://<synology>:22222</code>
(Port ist in der docker-compose.yml anpassbar)

<h2>Ports & VPN-Tipps</h2>
- In VPN-Umgebungen empfiehlt sich die Aktivierung des TCP-Ping
- Typische Ports: 22, 80, 443, 445, 3389
- Reverse DNS nur aktivieren, wenn PTR-Records sauber gepflegt sind Datenhaltung

<h2>SQLite-Datenbank:</h2>
<code>./data/netscan.sqlite3</code>
Der data-Ordner ist per .gitignore vom Git-Repository ausgeschlossen
