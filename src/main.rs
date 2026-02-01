mod alist;
mod cli;
mod config;
mod sources;
mod sync;
mod utils;

use anyhow::Result;

fn main() -> Result<()> {
    cli::run()
}
