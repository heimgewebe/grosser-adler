# Großer Adler — Authority & Operating Contract v2

## Zweck
Großer Adler ist die unabhängige Supervisory Plane des Heimgewebe-Operator-Ökosystems: Observer, Auditor und Berater. Er prüft konkrete Arbeitsbehauptungen und Ergebnisse gegen Primärquellen. Er ist weder zweite Control Plane noch zweite Work-State-Autorität.

## Begriffe
- **controller**: steuert oder verantwortet eine Arbeit;
- **executor**: führt den konkreten Effekt aus;
- **subject**: Gegenstand der Arbeit;
- **artifact**: erzeugtes oder geprüftes Ergebnis;
- **runtime**: tatsächlich laufender Dienst, Prozess oder Deploymentzustand.
Diese Rollen dürfen nicht gleichgesetzt werden.

## Wahrheitsmodell
Grabowski-, Bureau-, Agenten- oder andere Operatorprojektionen sind Claims und Discovery-Hinweise, nicht automatisch die Wahrheit ihres eigenen Audits. Adler bevorzugt unabhängige Primärquellen: konkrete Runtime, zuständige Primärstores, Git/GitHub und gebundene Receipts. Partiell oder trunciert beobachtet bedeutet `unknown`/`incomplete`, niemals Abwesenheit. `supervise_work` verifiziert eine explizite Binding-/Claim-Beschreibung und persistiert keinen Work-State. Bestätigung gilt pro Evidenzdimension. Grabowski-Lane-, Bureau-Task- und Agent-Run-Identitäten bleiben in v1 ohne direkten Primäradapter `unverified`; selbst bei bestätigtem Git-/Runtime-Zustand bleibt der Gesamtstatus dann `incomplete`. PR-Bindungen können dagegen über die exakte GitHub-PR-Identität direkt bestätigt oder widersprochen werden.

## Trust Boundary
Eigener MCP-Prozess, eigener OpenAI-Tunnel, eigener Toolkatalog; keine Verwendung des Grabowski-MCP als Beobachtungsbackend; direkte Git-/GitHub-/systemd-/Prozessbeobachtung; keine eigene kanonische Arbeitsdatenbank.

Credentials bleiben getrennte Secret-Domänen. Der Tunnel lädt ausschließlich `%h/.config/tunnel-client/grosser-adler-runtime.env`. Der MCP-Dienst kann `%h/.config/grosser-adler/github.env` laden; dessen `GROSSER_ADLER_GITHUB_TOKEN` wird vom Server ausschließlich für `/usr/bin/gh` als `GH_TOKEN` weitergereicht. Git, systemd, `ps`, `ss` und andere Subprozesse erhalten dieses Credential nicht. Fehlt das dedizierte GitHub-Credential, schlagen GitHub-Reads fail-closed fehl. Ausgaben aller erlaubten Subprozesse durchlaufen die zentrale Secret-Redaction.

Der MCP-Dienst bindet ausschließlich Loopback. Ein eigener tunnel-client-Prozess verbindet ihn mit dem dedizierten OpenAI-Tunnel `großer-adler`.

## Read Capabilities
- Git status/log/show unter `/home/alex/repos`;
- GitHub PR-Metadaten, Reviews und Checks;
- Discovery und Status aller syntaktisch gültigen **user-systemd** Services ohne Namens-Allowlist;
- bounded Journal-Reads;
- Service-Runtime-Korrelation auf MainPID, **same-UID und service-cgroup-gebundene** Prozessnachkommen, Prozessname, Ressourcen und sichtbare Listener;
- explizite Claim-Verifikation über `supervise_work`;
- eigener Finding-Store.
Es gibt keinen generischen Terminal-, Shell-, ptrace-, Signal- oder Service-Control-Endpunkt und keinen öffentlichen generischen Prozess-PID-Reader. Prozess-argv und Prozessumgebungen werden in v1 nicht ausgegeben; Prozesssicht entsteht nur im Kontext eines ausgewählten Services und dessen cgroup. Systemweite Root-/Docker-/Nix-Sicht ist nicht Bestandteil von v1.

## Einziger Write-Pfad
`submit_finding` schreibt genau einen create-only Datensatz in den Adler-Finding-Store. Er kann Beobachtungen, Widersprüche, fehlende Evidenz, Risiken, Advice und Recheck-Bedarf ausdrücken. Advice ist Datenmaterial, keine Ausführungsautorität. Relationale Aussagen binden alle zustandsrelevanten Komponenten über `checkpoint_components`. Der kanonische Komponenten-Hash bindet die gesamte Menge; ändert sich eine Komponente, gilt `all_components_must_match_or_recheck`. Legacy-Single-Checkpoint-Findings bleiben kompatibel. Findings starten niemals automatisch Tasks, Leases, Merges oder Deployments.

## Verbotene Effekte
Kein File-Writer außerhalb des Finding-Stores, kein Commit/Push/Merge, keine GitHub-Mutation, kein Deployment, kein Service start/stop/restart, kein Prozesssignal, kein Root, keine Bureau-Mutation, keine Work-Lane oder Lease, kein Agentenstart, kein Secret-Reveal.

## Supervisor-Ablauf
1. Eine bestehende Authority oder der Aufrufer liefert eine starke Binding-Identität und eine konkrete Behauptung.
2. Adler liest unabhängige Primärquellen.
3. Adler antwortet `confirmed`, `contradicted`, `stale`, `incomplete` oder `unknown`.
4. Nur eine entscheidungsrelevante Abweichung rechtfertigt ein Finding/Advice.
5. Der zuständige Controller entscheidet über jede Aktion.

## Anti-Doppelbau
Adler erzeugt keinen eigenen Lifecycle und kein globales Work-Register. Vor jeder neuen Read-Oberfläche gilt reuse-before-build. Cross-Work- und Portfolio-Aussagen bleiben hinter einem Nutzengate.
