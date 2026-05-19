# Threat Intel

macOS threat intelligence dashboard — ingests, correlates, and visualizes threats from multiple open-source feeds.

## Features

- **Multi-source ingestion** — RSS/Atom feeds, AlienVault OTX, AbuseIPDB, SANS ISC
- **Bento grid dashboard** — severity-coded threat cards with live search and source/severity filtering
- **10-day ingestion window** — configurable backlog depth (3–25 days) via Settings
- **Search & filter** — real-time keyword search across titles and descriptions, severity sidebar filters, and per-feed filtering from ingestion results
- **Background sync** — runs ingestion on a configurable schedule
- **Local persistence** — SQLite via GRDB, deduplicated by content hash

## Requirements

- macOS 15+
- Xcode 16+
- Swift 6+

## Setup

1. Clone the repo
2. Open `Threat-Intel.xcodeproj` in Xcode
3. Build and run (⌘R)
4. Add API keys for OTX / AbuseIPDB in Settings if desired — feeds work without keys

### Default Feeds

| Feed | URL |
|------|-----|
| SANS ISC | https://isc.sans.edu/rssfeed.xml |
| Week in OSINT | https://medium.com/feed/week-in-osint |
| Bellingcat | https://www.bellingcat.com/feed/ |
| IntelTechniques | https://inteltechniques.com/blog/feed/ |
| OpenPhish | https://openphish.com/feed.txt |
| BleepingComputer | https://www.bleepingcomputer.com/feed/ |

## Architecture

```
Threat-Intel/
├── App/                # App entry, DI container
├── Core/
│   ├── Models/         # ThreatItem, ThreatSource, Indicator, FeedEntry
│   ├── Networking/     # APIClient, IngestionOrchestrator, RateLimiter, BackgroundSync
│   ├── Storage/        # GRDB database, repository, source manager, keychain
│   └── Utilities/      # Hash util, array extensions
├── Features/
│   ├── Dashboard/      # Main dashboard view + view model
│   ├── Sources/        # Source config (Settings) view + view model
│   ├── Feeds/          # RSS/Atom feed parsing
│   └── ThreatIntel/    # OTX, AbuseIPDB, SANS service integrations
└── Tests/              # Unit tests
```

## License

MIT
