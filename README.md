<h1>Netzwerkscanner</h1>
Kleine Weboberfläche (Docker- und Synology-tauglich), mit der sich per Klick IP-Bereiche – auch über Site-to-Site-VPN – scannen lassen. Gefundene Geräte werden inklusive Hostname als Up/Down angezeigt.

Zusätzlich können pro IP Alias-Namen und Notizen gespeichert werden, die bei späteren Scans automatisch wieder erscheinen.
Über die Oberfläche lassen sich frei konfigurierbare Preset-Buttons für häufig genutzte IP-Bereiche anlegen.

<h2>Funktionen</h2>
- Preset-Buttons für IP-Bereiche (Name + Range)<br>
- Manuelle Eingabe von IP-Bereichen:<br>
&nbsp;&nbsp;&nbsp;&nbsp;z. B. 10.10.0.0/24 oder Start–Ende (z. B. 10.10.0.10-10.10.0.50)<br>
- Scan via nmap -sn<br>
- Optionaler TCP-Ping auf definierte Ports (empfohlen für VPN-Umgebungen)<br>
   - Optionales Reverse DNS<br>
- Alias-Namen und Notizen pro IP (persistent in SQLite)<br>
- Eigene Einstellungsseite zum Verwalten der Presets<br>

<h2>Docker</h2>
Repository klonen<br>
&nbsp;<code>git clone https://github.com/Wolf6660/Netzwerkscanner.git</code><br>
In das Projektverzeichnis wechseln<br>
&nbsp;<code>cd Netzwerkscanner</code><br>
Optional: Port oder andere Einstellungen anpassen<br>
&nbsp;<code>nano docker-compose.yml</code><br>
Container bauen und starten<br>
&nbsp;<code>docker compose up -d --build</code><br>
Weboberfläche aufrufen<br>
&nbsp;<code>http://<IP-oder-Hostname-des-Servers>:22222</code><br>

<h2>Synology (Container Manager)</h2>
- Repository/Ordner auf die Synology kopieren<br>
&nbsp;&nbsp;&nbsp;&nbsp;   z. B. nach /volume1/docker/netscan-web<br>
&nbsp;&nbsp;&nbsp;&nbsp;  (GitHub → grüner Code-Button → Download ZIP)<br>
- Container Manager → Projekt → Erstellen<br>
- Ordner auswählen und die Abfrage zur Nutzung der docker-compose.yml bestätigen<br>
- Projekt starten<br>
- Weboberfläche öffnen
&nbsp;<code>http://<synology>:22222</code><br>
&nbsp;&nbsp;&nbsp;&nbsp;(Port ist in der docker-compose.yml anpassbar)<br>

<h2>Ports & VPN-Tipps</h2>
- In VPN-Umgebungen empfiehlt sich die Aktivierung des TCP-Ping<br>
- Typische Ports: 22, 80, 443, 445, 3389<br>
- Reverse DNS nur aktivieren, wenn PTR-Records sauber gepflegt sind Datenhaltung<br>

<h2>SQLite-Datenbank:</h2>
&nbsp;<code>./data/netscan.sqlite3</code>
Der data-Ordner ist per .gitignore vom Git-Repository ausgeschlossen
