# Moosage - HackMyVM (Hard)

![Moosage.png](Moosage.png)

## Übersicht

*   **VM:** Moosage
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Moosage)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 13. November 2022
*   **Original-Writeup:** https://alientec1908.github.io/Moosage_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Moosage" zu erlangen. Der Weg dorthin begann mit der Entdeckung eines exponierten `.git`-Verzeichnisses auf dem Webserver der `/blog`-Anwendung. Durch Analyse des Quellcodes (oder der Konfigurationsdateien) aus dem Git-Repository wurden Standard-Admin-Credentials (`demo:demo`) gefunden. Nach dem Login in die Blog-Anwendung wurde eine (nicht detailliert beschriebene) Schwachstelle ausgenutzt, um eine Reverse Shell als `www-data` zu erlangen. Die erste Rechteausweitung zum Benutzer `baca` gelang durch das Auslesen von MySQL-Datenbank-Credentials (`baca:youareinsane`) aus einer Konfigurationsdatei (`config.ini`) und anschließender Verwendung dieser Credentials mit `su`. Die finale Eskalation zu Root erfolgte durch Ausnutzung einer unsicheren `cowsay`-Implementierung. Es wurde eine benutzerdefinierte `.cow`-Datei erstellt, die beim Aufruf (vermutlich durch einen als Root laufenden Prozess wie ein Login-Skript) eine SUID-Bash-Kopie in `/tmp` erstellte. Diese SUID-Bash wurde dann ausgeführt, um Root-Rechte zu erlangen.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi` / `nano`
*   `nmap`
*   `gobuster`
*   `nikto`
*   `wfuzz`
*   `sqlmap` (versucht)
*   `hydra` (versucht)
*   `dirsearch`
*   `git-dumper`
*   `pip`
*   `nc` (netcat)
*   Python3 (`pty` Modul für Shell-Stabilisierung)
*   `mysql`
*   `cowsay` (als Angriffsvektor)
*   `ssh`
*   Standard Linux-Befehle (`ls`, `cat`, `sudo` (versucht), `find`, `ss`, `su`, `echo`, `cp`, `chmod`, `mkdir`, `id`, `cd`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Moosage" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.110) mit `arp-scan` identifiziert. Hostname `moosage.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 7.9p1) und Port 80 (HTTP, Nginx 1.14.2) mit dem Titel "Moosage - login".
    *   `gobuster` fand das Verzeichnis `/blog/`.
    *   Weitere Enumeration mit `gobuster` und `dirsearch` auf `/blog/` fand ein exponiertes `.git`-Verzeichnis (`/blog/.git/HEAD`).

2.  **Initial Access (RCE als `www-data` via Git Leak & Blog Exploit):**
    *   Mittels `git-dumper` wurde das Git-Repository von `http://moosage.hmv/blog/.git` heruntergeladen.
    *   In der Datei `.git/config` wurde die URL zum originalen GitHub-Repository `https://github.com/m1k1o/blog` gefunden.
    *   Analyse dieses Repositories (oder der lokalen Kopie) enthüllte Standard-Admin-Credentials (`demo:demo`) in einer `config.ini`-Datei.
    *   Login in die Blog-Anwendung (`http://192.168.2.110/blog/`) mit `demo:demo`.
    *   Durch Ausnutzung einer (nicht detailliert beschriebenen) Schwachstelle in der Blog-Anwendung wurde eine Reverse Shell zu einem Netcat-Listener als `www-data` aufgebaut und stabilisiert.

3.  **Privilege Escalation (von `www-data` zu `baca` via DB Credentials):**
    *   Als `www-data` wurde die Konfigurationsdatei `/var/www/html/blog/config.ini` (oder ein ähnlicher Pfad) gefunden.
    *   Diese Datei enthielt MySQL-Zugangsdaten: Benutzer `baca`, Passwort `youareinsane` für die Datenbank `moosage`.
    *   Mit `su baca` und dem Passwort `youareinsane` wurde erfolgreich zum Benutzer `baca` gewechselt.
    *   Die User-Flag (`hmvmessageme`) wurde in `/home/baca/user` gefunden.

4.  **Privilege Escalation (von `baca` zu `root` via `cowsay` SUID Exploit):**
    *   Als `baca` wurde eine benutzerdefinierte `cowsay`-Datei (`cower.cow`) im Verzeichnis `/usr/share/cowsay/cows/` erstellt.
    *   Der Inhalt dieser Datei war so präpariert, dass beim Aufruf von `cowsay` mit dieser `.cow`-Datei ein Shell-Befehl ausgeführt wird: `echo "\$the_cow = \$(cp /bin/bash /tmp/bash && chmod +s /tmp/bash)" > /usr/share/cowsay/cows/cower.cow`.
    *   Es wurde SSH-Zugang für `baca` eingerichtet, indem ein Public Key in `~/.ssh/authorized_keys` platziert wurde.
    *   Nach einem SSH-Login als `baca` zeigte die Willkommensnachricht (die `cowsay` verwendete) an, dass der Exploit ausgelöst wurde.
    *   Im `/tmp`-Verzeichnis wurde die Datei `bash` gefunden (eine Kopie von `/bin/bash` mit gesetztem SUID-Bit).
    *   Durch Ausführen von `/tmp/bash -p` wurde eine Root-Shell erlangt.
    *   Die Root-Flag (`hmvyougotmooooooo`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Exponiertes `.git`-Verzeichnis:** Ermöglichte das Herunterladen des Quellcodes und der Konfigurationsdateien der Webanwendung, was zur Aufdeckung von Standard-Credentials führte.
*   **Standard-Credentials:** Die Blog-Anwendung verwendete Standard-Admin-Logins (`demo:demo`).
*   **RCE in Webanwendung:** Eine nicht näher spezifizierte Schwachstelle in der Blog-Anwendung ermöglichte RCE als `www-data`.
*   **Klartext-Datenbank-Credentials in Konfigurationsdatei:** Zugangsdaten zur MySQL-Datenbank waren im Klartext in `config.ini` gespeichert.
*   **Unsichere `cowsay`-Implementierung / Privilege Escalation:** Die Möglichkeit, als normaler Benutzer `.cow`-Dateien in einem Systemverzeichnis zu erstellen, die dann von einem Prozess mit höheren Rechten (hier implizit Root, z.B. beim Login-MOTD) ausgeführt werden, führte zur Erstellung einer SUID-Root-Shell.

## Flags

*   **User Flag (`/home/baca/user`):** `hmvmessageme`
*   **Root Flag (`/root/root.txt`):** `hmvyougotmooooooo`

## Tags

`HackMyVM`, `Moosage`, `Hard`, `Git Dumper`, `Default Credentials`, `Web RCE`, `Database Leak`, `MySQL`, `cowsay Exploit`, `SUID Exploit`, `Linux`, `Web`, `Privilege Escalation`, `Nginx`
