# Großer Adler — Authority & Operating Contract

## Zweck

Großer Adler ist ein unabhängiger read-mostly Beobachter des Heimgewebe-Operator-Ökosystems. Er prüft aktuelle Primärquellen selbst und behandelt Grabowski-Ausgaben nur als eine mögliche Quelle unter mehreren.

## Trust Boundary

- eigener MCP-Prozess;
- eigener OpenAI-Tunnel;
- eigener Toolkatalog;
- keine Verwendung des Grabowski-MCP als Beobachtungsbackend;
- lokale Repositories werden direkt gelesen, GitHub direkt über einen read-fähigen Client und Runtime-Zustand direkt über systemd/journalctl.

## Read Capabilities

- Git status/log/show für Repositories unter `/home/alex/repos`;
- GitHub PR-Metadaten, Reviews und Checks;
- allowlist-gebundener user-systemd Status und Journal;
- eigener Finding-Store.

Es gibt keinen generischen Terminal- oder Shell-Endpunkt.

## Einziger Write-Pfad

`submit_finding` erzeugt genau eine neue JSON-Datei im Adler-Finding-Store. Die ID entsteht serverseitig, das Schreiben ist create-only (`O_EXCL`) und das Finding enthält Subject, Checkpoint, Severity, Summary, Evidence-Referenzen, Beobachtungszeit und Adler-Identity.

Ein Finding hat den Vertrag `advisory_only_no_automatic_action`. Es startet keinen Task, erwirbt keine Lease, verändert kein Repository, merged nichts und deployt nichts.

## Verbotene Effekte

Kein File-Writer außerhalb des Finding-Stores, kein Commit/Push/Merge, keine GitHub-Mutation, kein Deployment, kein Service start/stop/restart, kein Prozesssignal, kein Root, keine Bureau-Mutation, keine Work-Lane oder Lease, kein Secret-Reveal.

## Transport

Der MCP-Dienst bindet ausschließlich Loopback. Ein eigener tunnel-client-Prozess verbindet ihn mit dem dedizierten OpenAI-Tunnel `großer-adler`.

## Finding-Lifecycle

Adler → append-only Finding → Grabowski kann es lesen → Grabowski entscheidet über seine normalen Authority-Pfade. Findings werden nicht automatisch Bureau-Tasks und nicht automatisch Aktionen.

## Writer/Auditor-Ablauf

1. Thread A lässt Grabowski an einem PR oder Operator-Gegenstand arbeiten.
2. Thread B lässt Großer Adler denselben Gegenstand anhand Primärquellen prüfen.
3. Bei relevanter Abweichung legt der Adler ein checkpoint-gebundenes Finding ab.
4. Grabowski liest das Finding und entscheidet unabhängig, ob eine Aktion erforderlich ist.
5. Ändert sich der Head/Checkpoint, gilt das alte Finding nicht automatisch für den neuen Zustand.
