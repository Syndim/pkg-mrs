# pkg-mrs

Package Mirror CLI - Mirror packages from various sources (GitHub, Homebrew, Scoop) to Alist storage via offline download tasks.

## Build & Test

```bash
cargo build              # or: just b
cargo test               # or: just t
cargo build --release    # or: just r

# Run single test
cargo test test_name

# Run tests in specific module
cargo test config::tests
```

## Architecture

```
src/
├── main.rs          # Entry point
├── cli.rs           # CLI definition (clap) and command dispatch
├── sync.rs          # Sync command - batch mirroring from config
├── config.rs        # TOML config parsing with env var expansion
├── alist.rs         # Alist API client (file_exists, create_offline_download_task)
└── sources/         # Package source implementations
    ├── github.rs    # GitHub releases API
    ├── homebrew.rs  # Homebrew cask/formula manifest parser (.rb files)
    └── scoop.rs     # Scoop manifest parser (.json files)
```

### Data Flow

1. **CLI mode**: User runs `pkg-mrs github|homebrew|scoop` with args → source handler fetches manifest → extracts URLs → submits to Alist
2. **Config mode**: User runs `pkg-mrs sync` → loads `~/.config/pkg-mrs/config.toml` → iterates mirrors → dispatches to appropriate source handler

### Key Types

- `MirrorSource` enum in `config.rs` - typed source variants (Github/Homebrew/Scoop) parsed from TOML
- `CommonArgs` in `cli.rs` - shared CLI args (name, target, token, tool, regex)
- Each source has its own `*Args` struct and `handle()` function

## Conventions

### Adding a New Source

1. Create `src/sources/newname.rs` with:
   - `NewNameArgs` struct (include `#[command(flatten)] pub common: CommonArgs`)
   - `handle(args) -> Result<()>` function
   - Manifest parsing logic
2. Add to `src/sources/mod.rs`
3. Add variant to `Commands` enum in `cli.rs`
4. Add `MirrorSource::NewName` variant and `NewNameSource` struct in `config.rs`
5. Handle new variant in `run_mirror()` in `sync.rs`

### Config Environment Variables

Config values support `${VAR}` and `$VAR` syntax for environment variable expansion (processed before TOML parsing).

### Token Retrieval

Alist tokens are retrieved from KeePass database. Requires `KEEPASS_PASSWORD` env var set.

### Async Pattern

Sources use `tokio::runtime::Runtime::new()` to run async code from sync `handle()` functions:
```rust
pub fn handle(args: Args) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_handle(args))
}
```

## Rust Edition

This project uses Rust **2024 edition**. Note that `std::env::set_var` and `remove_var` are unsafe in this edition.
