mod alist;
mod cli;
mod config;
mod sources;

use anyhow::Result;

fn main() -> Result<()> {
    cli::run()
}
