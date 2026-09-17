# Großer Adler — Source Map v2

| Fakt | bevorzugte Authority | Adler-V1-Pfad | Semantik |
|---|---|---|---|
| lokaler HEAD / Dirty-State | Git | `git_status` | primär |
| Commitinhalt | Git | `git_show` | primär |
| PR-HEAD / Base / CI / Reviews | GitHub | `github_pr` | primär für GitHub |
| Servicezustand | user-/system-systemd | `service_status` | beobachtet beide Scopes; wählt genau einen aktiven/geladenen Scope, Doppelbelegung bleibt unbekannt |
| Service-Prozessbaum | Prozesssicht + aufgelöster systemd MainPID/ControlGroup | `service_runtime` | same-UID, cgroup-gebundene Hostbeobachtung im selben Scope |
| positive TCP/UDP-Listener-Evidenz | `ss` mit cgroup-Metadaten | `service_runtime` | nur positive cgroup-korrelierte Evidenz; kein Beweis für Abwesenheit |
| Grabowski-Lane-Ziel | Grabowski Work-Lane-Receipt + registrierter Git-Worktree | `get_work_target(lane_id)` | Autorität nur für `lane_id → repo/worktree/branch/purpose`; keine Aussage über Korrektheit der Arbeit |
| Bureau Task/Run | Bureau StateStore | kein V1-Adapter | unbekannt, bis ein realer Bedarf einen direkten Adapter rechtfertigt |
| Agent Run | Agent-/Workspace-Store | kein V1-Adapter | unbekannt, bis ein realer Bedarf einen direkten Adapter rechtfertigt |
| Adler Finding | Adler append-only Store | `list_findings` | kanonische Adler-eigene Beobachtungshistorie |
| aktuelle Lane-Sicht | Adler Finding Store + exaktes Lane-Ziel + aktueller Worktree-HEAD | `publish_worktree_inbox` | berechnete, ersetzbare Sicht; keine zweite Historie |

## Regeln
1. Primärevidenz vor Operatorzusammenfassung.
2. Fehlende, abgeschnittene oder nicht lesbare Quellen bleiben `incomplete`/`unknown`; keine negative Existenzaussage aus partieller Beobachtung.
3. `get_work_target` bestimmt nur das von Grabowski registrierte Arbeitsziel. Adler rekonstruiert die fachliche/technische Korrektheit weiterhin unabhängig aus Primärquellen.
4. Findings werden nicht über Task-, Checkout- oder Current-Work-Resolver zugeordnet. Lane-Zustellung benötigt die explizite `lane:<lane_id>`-Bindung.
5. Der zentrale Finding Store ist Historie; der externe Adler-Inbox-Store enthält nur checkpoint-gebundene aktuelle Sichten. `.adler/inbox.json` ist ein von Grabowski verwalteter Zeiger darauf.
6. V1 besitzt keinen `supervise_work`-Lifecycle, kein Adler-current_work, keine Delivery Queue, keine ACKs und keine Admission Engine.
7. Listener-Beobachtung belegt nur positiv zugeordnete TCP/UDP-Listener; ein leeres oder unvollständig attribuiertes Ergebnis ist keine Abwesenheitsbehauptung.
8. Identity-Felder, die Secret-Redaction benötigen würden, werden fail-closed abgewiesen statt identitätskollabierend gespeichert.
9. Gleichnamige User- und System-Units werden gemeinsam beobachtet. `active` und `reloading` gelten als laufend; konkurrierende `activating`-/`deactivating`-Zustände bleiben mehrdeutig. Genau ein laufender Scope gewinnt nur ohne konkurrierenden Übergang; sonst darf nur genau eine geladene Unit gewählt werden. Mehrdeutigkeit bleibt fail-closed.
