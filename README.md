# ActiveNet-API

Enterprise PowerShell solutions for integrating with the ACTIVENet REST API Gateway and synchronizing facility occupancy to Microsoft 365.

## Repository Overview

This repository is organized into two primary architectural domains:

```
ActiveNet-API/
├── API/                   # Reusable PowerShell Module & Client Tooling (v2.0.0)
│   ├── ActiveNetAPI.psd1  # Module Manifest v2.0.0 (Preserves PowerShell Gallery GUID)
│   ├── ActiveNetAPI.psm1  # Root Module
│   ├── Public/            # Hardened Public Functions
│   │   ├── Invoke-ActiveNetAPI.ps1
│   │   └── New-DynamicDigitalSignature.ps1
│   ├── Private/           # Security & Unmanaged Memory Helpers
│   ├── tests/             # Module Pester Unit Tests
│   └── README.md          # Module Documentation & Public Usage Guide
│
└── Sync-ActiveNetToM365/   # Calendar Reconciliation Solution (ACTIVENet -> M365)
    ├── config/            # Schema & Sanitized Configuration Examples
    ├── docs/              # Architecture, Security, & Prerequisites Specifications
    ├── logs/              # Rolling Execution Logs
    ├── src/               # Orchestration Scripts & Internal Modules
    │   ├── modules/       # Reconciliation, Graph, Locking, State, Conflict Detection
    │   └── Sync-ActiveNetToM365.ps1 # Sanitized Orchestrator with CLI Overrides
    ├── state/             # Atomic Local State Files & Schemas
    ├── tests/             # Comprehensive Pester Test Suite (Stages 3B, 3C, 3D)
    └── README.md          # Solution Architecture & Run Guide
```

---

## 1. ActiveNetAPI PowerShell Module (`API/`)

The `ActiveNetAPI` module (v2.0.0) provides a production-grade, hardened PowerShell client for ACTIVENet's REST API Gateway.

### Key Capabilities
- **PowerShell Compatibility**: Full support for both Windows PowerShell 5.1 (Desktop) and PowerShell Core 7.x+ (Core).
- **PowerShell Gallery Heritage**: Maintains existing GUID `ebe28e05-8dc6-4175-86d0-97b761d4bdb0`.
- **Memory Safety**: Uses unmanaged BSTR zero-freeing (`ZeroFreeBSTR`) for `[SecureString]` credentials.
- **Modern Cryptography**: Pure in-memory SHA-256 calculation (`[System.Security.Cryptography.SHA256]::Create()`).
- **Resilient HTTP Execution**: Automatic exponential backoff on HTTP 429 (Rate Limit / Over QPS) and HTTP 5xx errors.
- **Pagination & Gateways**: Built-in cursor pagination (`-AllPages`) and seamless US / Canada gateway routing (`-Canada`).
- **Standalone Execution**: `Invoke-ActiveNetAPI.ps1` and `New-DynamicDigitalSignature.ps1` can also be run as standalone scripts without importing the module.

For complete documentation and usage examples, see [`API/README.md`](file:///C:/Drive_D/Coding/Git/ActiveNet-API/API/README.md).

---

## 2. Sync-ActiveNetToM365 Calendar Synchronization (`Sync-ActiveNetToM365/`)

A single-purpose, highly defensive reconciliation engine designed to project room reservations from ACTIVENet into Microsoft 365 Room Mailbox calendars via Microsoft Graph v1.0.

### Key Capabilities
- **Strict Invariant Protection**: Guarantees zero modification, deletion, or movement of Outlook-native meetings.
- **Positive Ownership Verification**: Uses MAPI Single-Value Extended Properties and atomic JSON local state tracking.
- **Circuit Breakers**: Disables destructive actions (deletions) when API anomalies, schema mismatch, or truncation occurs.
- **Runtime Parameter Overrides**: Command-line parameters allow dynamic targeting of room mailboxes, facility IDs, and center IDs.

For solution architecture, setup instructions, and testing details, see [`Sync-ActiveNetToM365/README.md`](file:///C:/Drive_D/Coding/Git/ActiveNet-API/Sync-ActiveNetToM365/README.md).

---

## Author & License
- **Author**: Justin Romanello
- **License**: MIT
