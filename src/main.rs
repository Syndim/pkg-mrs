mod alist;
mod cli;
mod sources;

use anyhow::Result;

fn main() -> Result<()> {
    cli::run()
}
