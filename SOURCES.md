# Großer Adler — Source Map v1

| Fakt | bevorzugte Authority | Adler-v1-Pfad | Semantik |
|---|---|---|---|
| lokaler HEAD / Dirty-State | Git | `git_status` / `supervise_work` | primär |
| Commitinhalt | Git | `git_show` | primär |
| PR-HEAD / Base / CI / Reviews | GitHub | `github_pr` | primär für GitHub |
| User-Servicezustand | user-systemd | `service_status` | primär für Servicezustand |
| Service-Prozessbaum | Prozesssicht + systemd MainPID/ControlGroup | `service_runtime` | aktuelle same-UID, cgroup-gebundene Hostbeobachtung |
| sichtbare Listener | `ss` mit cgroup-Metadaten | `service_runtime` | cgroup-korreliert; fehlende/truncierte Attribution => incomplete |
| Grabowski Work/Lane | Grabowski Stores/Projektionen | caller claim in v1 | Claim/Discovery, nicht Adler-Autorität |
| Bureau Task/Run | Bureau StateStore | caller claim in v1 | Claim bis direkter Adapter nötig/belegt |
| Agent Run | Agent/Workspace-Store | caller claim in v1 | Claim bis direkter Adapter nötig/belegt |
| Adler Finding | Adler append-only store | `list_findings` | Adler-eigene Advisory-Evidenz |

## Regeln
1. `supervise_work` persistiert keinen Work-State.
2. Ein Claim wird nur in unabhängig belegten Dimensionen bestätigt; eine bestätigte Evidenzdimension bestätigt keine unaufgelöste Lane-/Task-/Agent-Identität.
3. Fehlende, abgeschnittene oder nicht lesbare Quellen bleiben `incomplete`/`unknown`.
4. Keine negative Existenzaussage aus partieller Beobachtung.
5. Neue Adapter nur, wenn ein realer Pilotfall mit bestehenden Reads nicht sinnvoll prüfbar ist.
6. Cross-Work-Konflikte später nur über starke gemeinsame Schlüssel.
