# Großer Adler — Authority & Operating Contract

## Zweck

Großer Adler ist ein unabhängiger read-mostly Beobachter des Heimgewebe-Operator-Ökosystems. Er prüft aktuelle Primärquellen selbst und behandelt Grabowski-Ausgaben nur als eine mögliche Quelle unter mehreren.

## Trust Boundary

- eigener MCP-Prozess;
- eigener OpenAI-Tunnel;
- eigener Toolkatalog;
- keine Verwendung des Grabowski-MCP als Beobachtungsbackend;
- lokale Repositories werden direkt gelesen, GitHub direkt über einen read-fähigen Client und Runtime-Zustand direkt über systemd/journalctl.

Credentials sind getrennte Secret-Domänen. Der Tunnel lädt ausschließlich `%h/.config/tunnel-client/grosser-adler-runtime.env`. Der MCP-Dienst kann `%h/.config/grosser-adler/github.env` laden; dessen `GROSSER_ADLER_GITHUB_TOKEN` wird vom Server ausschließlich für `/usr/bin/gh` als `GH_TOKEN` weitergereicht. Git, systemd und andere Subprozesse erhalten dieses Credential nicht. Fehlt das dedizierte GitHub-Credential, schlagen GitHub-Reads fail-closed fehl.

## Read Capabilities

- Git status/log/show für Repositories unter `/home/alex/repos`;
- GitHub PR-Metadaten, Reviews und Checks;
- allowlist-gebundener user-systemd Status und Journal;
- eigener Finding-Store.

Es gibt keinen generischen Terminal- oder Shell-Endpunkt.

## Einziger Write-Pfad

`submit_finding` erzeugt genau eine neue JSON-Datei im Adler-Finding-Store. Die ID entsteht serverseitig, das Schreiben ist create-only (`O_EXCL`) und das Finding enthält Subject, Checkpoint, Severity, Summary, Evidence-Referenzen, Beobachtungszeit und Adler-Identity.

Bei relationalen Aussagen muss der Aufrufer `checkpoint_mode="relational"` setzen und mindestens zwei `checkpoint_components` für alle zustandsrelevanten Seiten binden, etwa `local_head` und `upstream_head` oder `pr_head` und `base_head`. Fehlende oder nur einseitige Komponenten werden fail-closed abgewiesen. `github_pr` liefert dafür sowohl `headRefOid` als auch `baseRefOid`. Der kanonische `checkpoint_set_sha256` bindet die gesamte Komponentenmenge. Ändert sich auch nur eine abhängige Komponente, gilt `all_components_must_match_or_recheck`: Das Finding darf nicht als weiterhin frisch behandelt werden, sondern benötigt einen Recheck. Einfache, nichtrelationale Findings bleiben aus Kompatibilitätsgründen im Standardmodus `single` beim bisherigen einzelnen `checkpoint`; dieser Modus akzeptiert keine Komponenten.

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
5. Ändert sich bei einem relationalen Finding eine gebundene Checkpoint-Komponente, gilt das alte Finding nicht automatisch für den neuen Zustand und muss vor Nutzung neu geprüft werden.
