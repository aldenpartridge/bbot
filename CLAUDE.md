# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Workflow

### Environment Setup
```bash
# Clone and set up development environment
git clone git@github.com:<username>/bbot.git
cd bbot
curl -sSL https://install.python-poetry.org | python3 -
poetry install
poetry run pre-commit install
poetry shell
```

### Common Development Commands

```bash
# Code formatting and linting
ruff format                    # Format code
ruff check                     # Lint code
poetry run ruff format         # Format via poetry
poetry run ruff check          # Lint via poetry

# Testing
poetry run pytest              # Run all tests (takes ~30 minutes)
poetry run pytest -k test_module_sslcert  # Run specific module test
poetry run pytest -k "test_module_ and not test_module_sslcert"  # Run all but one
poetry run pytest --log-cli-level=DEBUG  # Enable debug output

# Quick test runner (includes formatting + linting + specific tests)
./bbot/test/run_tests.sh                   # Run all tests
./bbot/test/run_tests.sh mymodule          # Run specific module tests

# BBOT commands for testing
bbot -t example.com -m mymodule           # Test your module
bbot -t example.com -p subdomain-enum     # Test with preset
bbot --list-modules                       # List all modules
bbot --list-presets                       # List all presets
```

### Module Development Requirements

1. **Create Module File**: Add `.py` file to `bbot/modules/`
2. **Inherit from BaseModule**: Class name must match filename (case-insensitive)
3. **Define Core Attributes**:
   - `watched_events`: Event types to process
   - `produced_events`: Event types to emit
   - `flags`: Must include "safe"/"aggressive" AND "passive"/"active"
   - `meta`: Module metadata (description, author, auth_required)
   - `options` / `options_desc`: Configurable options

4. **Key Methods**:
   - `setup()`: One-time initialization (return True/None/False)
   - `handle_event()`: Main event processing logic
   - `emit_event()`: Emit new events with parent context

5. **Testing Requirements**:
   - Every module **must** have a custom test in `bbot/test/test_step_2/module_tests/`
   - Test filename must be `test_module_<module_name>.py`
   - Tests must verify actual functionality, not just loading
   - Use `ModuleTestBase` for common testing utilities

## Project Overview

**BBOT** (BEE·bot - "BIGHUGE BLS OSINT Tool") is a multipurpose security reconnaissance and OSINT automation platform designed for subdomain enumeration, bug bounty reconnaissance, attack surface management, web application scanning, cloud resource discovery, and email/personnel discovery.

BBOT features an event-driven architecture with 150+ specialized modules that operate on a queue-based system for recursive reconnaissance.

### Key Features

- **Event-Driven Architecture**: Recursive reconnaissance engine with 150+ specialized modules
- **Flexible Module System**: Easy to extend with custom modules
- **Multiple Target Types**: DNS names, IPs, IP ranges, URLs, email addresses, organizations, usernames
- **Rich Output Options**: Neo4j, PostgreSQL, MySQL, SQLite, JSON, CSV, Elasticsearch, Splunk, webhooks
- **Async-First Design**: High concurrency for fast scanning
- **Smart Scope Management**: Strict/loose modes with configurable search distance
- **Preset System**: Quick scan configurations for common use cases

### Documentation

- **Full Documentation**: [https://www.blacklanternsecurity.com/bbot/](https://www.blacklanternsecurity.com/bbot/)
- **Module Development**: [docs/dev/module_howto.md](docs/dev/module_howto.md)
- **Architecture Details**: [docs/dev/architecture.md](docs/dev/architecture.md)
- **Scanner API**: [docs/dev/scanner.md](docs/dev/scanner.md)

---

## Core Architecture

BBOT's architecture is built on four fundamental concepts: Events, Modules, Queues, and the Scanner.

### Event System
Events are the fundamental data structure in BBOT. Every piece of discovered data becomes an event (DNS_NAME, IP_ADDRESS, URL, FINDING, etc.). Key characteristics:

- **Immutable**: Event data cannot be modified once created
- **Deterministic ID**: Event ID is based on type + data hash for automatic deduplication
- **Parent Tracking**: Events know their parent, creating discovery chains
- **Scope Distance**: Tracks "hops" from original target (0 = in-scope)
- **Tags**: Descriptive metadata (e.g., `mx-record`, `in-scope`, `http-title-admin-panel`)

Located in: `bbot/core/event/base.py`

### Module System
Modules process events and emit new events:

- **Watch Events**: Each module specifies `watched_events` it processes
- **Produce Events**: Modules emit events defined in `produced_events`
- **Flags**: Categorize modules (passive/active, safe/aggressive, etc.)
- **Queue Architecture**: Every module has incoming/outgoing queues

Located in: `bbot/modules/base.py`

### Scanner Orchestration
The Scanner class coordinates the entire scan:

- Loads and initializes modules
- Manages scan lifecycle (NOT_STARTED → STARTING → RUNNING → FINISHING → FINISHED)
- Tracks statistics per module
- Handles event routing via ScanIngress/ScanEgress

Located in: `bbot/scanner/scanner.py`

### Preset System
YAML-based scan configurations that specify:
- Modules to enable/disable
- Configuration overrides
- Output modules
- Scope and distance settings

Located in: `bbot/presets/` and referenced in `bbot/scanner/preset/`

### Configuration System

BBOT uses hierarchical configuration (OmegaConf):
1. `bbot/defaults.yml` - Global defaults
2. `~/.config/bbot/bbot.yml` - User configuration
3. Preset YAML files - Scan-specific configs
4. CLI arguments via `-c` flag

Example user config for API keys:
```yaml
modules:
  shodan:
    api_key: "your_key_here"
  github:
    api_key: "your_token_here"
```

## Important Development Notes

- **Module Name Matching**: Module filename must match class name (case-insensitive)
- **Flags are Required**: Every module needs safety categorization + activity level
- **Event Deduplication**: BBOT automatically deduplicates events by ID
- **Scope Management**: Use `scope_distance_modifier` to control event acceptance
- **Dependencies**: Use `deps_*` attributes for automatic installation via Ansible
- **API Keys**: Store in user config, never commit to repository
- **Error Handling**: Use logging functions like `self.hugesuccess()`, `self.error()`, etc.

## Testing Philosophy

BBOT takes testing seriously. Every module must have comprehensive tests that verify actual functionality. The project uses:

- **ruff** for linting and formatting
- **pytest** with async support for testing
- Two-step testing process: core functionality tests + module-specific tests
- Mock HTTP/DNS servers for isolated testing
- Coverage reporting to ensure test quality

## Key Project Structure

```
bbot/
├── bbot/                        # Main Python package
│   ├── core/                    # Core engine and infrastructure
│   │   ├── event/              # Event system (BaseEvent)
│   │   ├── helpers/            # Reusable utilities (DNS, web, etc.)
│   │   └── modules.py          # Module loader and manager
│   ├── modules/                # 150+ reconnaissance modules
│   │   ├── base.py             # BaseModule abstract class
│   │   ├── templates/          # Module base classes
│   │   ├── output/             # Output modules (neo4j, json, csv)
│   │   └── internal/           # Core functionality modules
│   ├── scanner/                # Scan orchestration
│   │   ├── scanner.py          # Main Scanner class
│   │   ├── manager.py          # Event routing (ScanIngress/ScanEgress)
│   │   └── preset/             # Preset system
│   ├── presets/                # Built-in YAML scan configurations
│   └── test/                   # Test suite (pytest-based)
├── docs/                       # Comprehensive documentation
└── pyproject.toml              # Poetry dependencies and metadata
```

### Important Directories

- **[bbot/core/](bbot/core/)**: Core engine, event system, configuration, and helper functions
- **[bbot/modules/](bbot/modules/)**: All scan, output, and internal modules
- **[bbot/scanner/](bbot/scanner/)**: Scanner orchestration and event management
- **[bbot/presets/](bbot/presets/)**: Built-in YAML preset configurations
- **[bbot/test/](bbot/test/)**: Comprehensive pytest-based test suite
- **[docs/dev/](docs/dev/)**: Developer documentation and guides

## Additional Resources

- **Official Documentation**: [https://www.blacklanternsecurity.com/bbot/](https://www.blacklanternsecurity.com/bbot/)
- **GitHub Repository**: [https://github.com/blacklanternsecurity/bbot](https://github.com/blacklanternsecurity/bbot)
- **Discord Community**: [https://discord.com/invite/PZqkgxu5SA](https://discord.com/invite/PZqkgxu5SA)
- **Module Development Guide**: [docs/dev/module_howto.md](docs/dev/module_howto.md)
- **Architecture Details**: [docs/dev/architecture.md](docs/dev/architecture.md)

For detailed API documentation and user guides, refer to the official documentation linked above.
