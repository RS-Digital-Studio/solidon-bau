# solidon-bau

Bauläufe für [Solidon](https://solidon3d.de/). Dieses Repository enthält keinen
Quelltext von Solidon, sondern nur die Workflows, mit denen er gebaut und geprüft
wird, und ein kleines Werkzeug, das sie auf den Läufern brauchen.

Der Quellstand eines Laufs kommt verschlüsselt als Asset eines unveröffentlichten
Release-Entwurfs und wird nur auf dem Läufer geöffnet. Was ein Lauf hochlädt, ist
ebenfalls verschlüsselt, und ins Protokoll eines Schritts schreibt er nur Zahlen und
seinen Ausgang. Läufe startet allein der Betreiber; es gibt keine Auslöser für
Pushes, Pull Requests oder Zeitpläne.

Ein Zwischenspeicher von Actions hält nur Bauergebnisse fremder Bibliotheken aus
öffentlichem Quellstand: Der Lauf `csharp-plattformen.yml` legt dort OpenCASCADE ab,
was eigenen Code enthält, baut jeder Lauf neu. Ein Eintrag wird nur benutzt, wenn die
Prüfsumme seines Inhalts in der verschlüsselten Quelle steht.

Alles hier wird aus dem privaten Repository erzeugt. Änderungen von Hand gehen beim
nächsten Abgleich verloren.

| Ort | Inhalt |
|---|---|
| `.github/workflows/` | die Workflows |
| `werkzeug/bau.py` | Entschlüsseln, Verschließen, stille Schritte |
| `werkzeug/box.swift` | dieselbe Verschlüsselung für die Signierjobs auf dem Mac |
| `werkzeug/requirements.txt` | die feste Fassung von `cryptography` für `bau.py` |
