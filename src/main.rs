mod alist;
mod cli;
mod config;
mod sources;
mod sync;

use anyhow::Result;

fn main() -> Result<()> {
    cli::run()
}
