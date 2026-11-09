# ACTIVENet Facility Management to Microsoft 365 Calendar Synchronization

**Authoritative Source**: ACTIVENet Facility Management  
**Destination**: Microsoft 365 Room Mailbox Calendar  
**Implementation Language**: PowerShell 7 (`pwsh`)  
**Execution Host**: Windows Server 2022 / Scheduled Task / Container  

---

## 1. Project Purpose & Flow
This solution provides a robust, one-way **occupancy projection** from ACTIVENet into Microsoft 365. It makes room bookings originating in ACTIVENet visible on the Exchange Online / Outlook calendar of the room resource without creating a complex two-way booking mechanism.

```
ACTIVENet Facility Management
      │
      ▼ (GetFacilitySchedules)
PowerShell 7 Synchronization Engine (Overnight Scheduled Task)
      │
      ▼ (Microsoft Graph v1.0 / Application Auth)
Microsoft 365 Room Mailbox Calendar
```

---

## 2. Core Safety Invariants

1. **Absolute Protection of Outlook-Native Meetings**:
   - The sync engine reads Outlook-created meetings solely for conflict detection.
   - It **NEVER** modifies, deletes, moves, reschedules, or takes ownership of an event not created by this application.
   - Similarity in subject, date, time, organizer, or room is **never** accepted as proof of ownership.
2. **Dual-Layer Positive Ownership Proof**:
   - Every synchronized item is tagged with a custom MAPI Single-Value Extended Property (`ActiveNetSyncOwned = True`) and a deterministic correlation key (`ActiveNetSourceId`).
   - Mutations and deletions are strictly restricted to events possessing this verified property.
3. **Destructive Operation Circuit Breaker**:
   - Deletions are forbidden if ACTIVENet retrieval fails, times out, paginates incorrectly, or reports abnormal truncation.
4. **Strict Idempotency**:
   - Successive executions with no changes generate 0 creates, 0 updates, 0 deletes.

---

## 3. Directory Layout

```
Sync-ActiveNetToM365/
├── config/
│   ├── config.schema.json         # JSON schema for configuration
│   └── config.example.json        # Template configuration (zero secrets, sanitized)
├── docs/
│   ├── ARCHITECTURE.md            # Technical & functional architecture
│   ├── IMPLEMENTATION_PLAN.md     # Implementation milestones
│   └── PREREQUISITES_CHECKLIST.md # Entra ID, certificate, Exchange Online, and host setup
├── logs/                          # Daily rolling log files (retained for 90 days)
├── src/
│   ├── modules/                   # Internal reconciliation modules
│   │   ├── ActiveNetClient.psm1   # ACTIVENet API client & signature generator
│   │   ├── ConflictDetector.psm1  # Half-open interval overlap & conflict detection
│   │   ├── EventModel.psm1        # Normalized internal event data structures
│   │   ├── GraphClient.psm1       # Microsoft Graph calendar API client
│   │   ├── Locking.psm1           # Single-instance file locking & stale-lock reclamation
│   │   ├── Logging.psm1           # Daily rolling logging & summary block formatter
│   │   ├── ReconciliationEngine.psm1 # Diff engine, action classifier, & circuit breaker
│   │   ├── Security.psm1          # Windows DPAPI secret loading & Entra ID JWT auth
│   │   └── StateManager.psm1      # Atomic local JSON state manager
│   └── Sync-ActiveNetToM365.ps1   # Main orchestrator script with CLI parameter overrides
├── state/
│   ├── state.schema.json          # JSON schema for synchronization state
│   └── state.example.json         # Example persistent correlation state
└── tests/
    ├── Stage3B.CoreModules.Tests.ps1    # Core module unit tests
    ├── Stage3C.Reconciliation.Tests.ps1 # Reconciliation and conflict engine tests
    └── Stage3D.DryRun.Tests.ps1         # End-to-end dry-run and write isolation tests
```

---

## 4. Execution & CLI Overrides

### Dry-Run Simulation Mode (30-Day Window)
Simulates synchronization without making any changes to Microsoft 365 or local state:
```powershell
pwsh -File ./src/Sync-ActiveNetToM365.ps1 -ConfigPath ./config/config.json -DryRun
```

### Production Execution
```powershell
pwsh -File ./src/Sync-ActiveNetToM365.ps1 -ConfigPath ./config/config.json
```

### Command-Line Parameter Overrides
You can override target mailbox and facility targets dynamically at runtime:
```powershell
pwsh -File ./src/Sync-ActiveNetToM365.ps1 `
    -ConfigPath ./config/config.json `
    -RoomMailbox 'conference-b@example.com' `
    -ActiveNetOrgId 'your-org-id' `
    -ActiveNetCenterName 'Community Center Complex' `
    -ActiveNetCenterId 10 `
    -ActiveNetFacilityName 'Conference Room B' `
    -ActiveNetFacilityId 105 `
    -DryRun
```
