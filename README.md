# NetScan

Webbasierter IPv4-Netzwerkscanner für Docker/Synology. Frei definierbare Netzwerke erscheinen im Hauptmenü als Buttons. Ein Klick startet den Scan mit den hinterlegten Einstellungen.

## Funktionen

- Nmap-Hostscan für lokale und über Site-to-Site-VPN erreichbare Netzwerke
- MAC-Adresse und Hersteller, wenn sie aus dem lokalen Layer-2-Netz sichtbar sind
- optionale FRITZ!Box-Integration über TR-064 für MAC-Adresse und Gerätename in entfernten Netzen
- dauerhafte Aliase anhand von Netzwerk und MAC-Adresse; IP-Fallback, wenn über VPN keine MAC verfügbar ist
- automatische Migration der vorhandenen SQLite-Datenbank
- einfache Geräteklassifizierung anhand von Hostname und Hersteller

## Start

```sh
docker compose up -d --build
```

Danach ist NetScan unter `http://<synology-ip>:22222` erreichbar. Die Datenbank liegt ausschließlich in `./data` und wird nicht in Git eingecheckt.

## FRITZ!Box

In der FRITZ!Box einen eigenen Benutzer mit Heimnetz-Zugriff anlegen und in NetScan beim betreffenden Netzwerk `FRITZ!Box (TR-064)` wählen. Adresse, Benutzer und Passwort werden nur in der lokalen SQLite-Datenbank gespeichert. Fällt die Routerabfrage aus, wird der normale Nmap-Scan trotzdem angezeigt und die Oberfläche gibt eine Warnung aus.

## Einschränkungen

MAC-Adressen werden nicht durch Router oder Site-to-Site-VPN-Tunnel transportiert. Ohne Routerintegration kann ein entferntes Gerät daher nur anhand seiner IP identifiziert werden. Private WLAN-MAC-Adressen können sich außerdem ändern.
