// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::anyhow;
use clap::Parser as _;
use file_header::{
    add_headers_recursively, check_headers_recursively,
    license::spdx::{YearCopyrightOwnerValue, APACHE_2_0},
};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::{env, path::PathBuf};

fn main() -> anyhow::Result<()> {
    let rust_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let ignore_globset = ignore_globset()?;
    // Note: when adding headers, there is a bug where the line spacing is off for Apache 2.0 (see https://github.com/spdx/license-list-XML/issues/2127)
    let header = APACHE_2_0.build_header(YearCopyrightOwnerValue::new(2023, "Google LLC".into()));

    let cli = Cli::parse();

    match cli.subcommand {
        Subcommand::CheckAll => {
            let result =
                check_headers_recursively(&rust_dir, |p| !ignore_globset.is_match(p), header, 4)?;
            if result.has_failure() {
                return Err(anyhow!(
                    "The following files do not have headers: {result:?}"
                ));
            }
        }
        Subcommand::AddAll => {
            let files_with_new_header =
                add_headers_recursively(&rust_dir, |p| !ignore_globset.is_match(p), header)?;
            files_with_new_header
                .iter()
                .for_each(|path| println!("Added header to: {path:?}"));
        }
    }
    Ok(())
}

fn ignore_globset() -> anyhow::Result<GlobSet> {
    Ok(GlobSetBuilder::new()
        .add(Glob::new("**/.idea/**")?)
        .add(Glob::new("**/target/**")?)
        .add(Glob::new("**/.gitignore")?)
        .add(Glob::new("**/CHANGELOG.md")?)
        .add(Glob::new("**/Cargo.lock")?)
        .add(Glob::new("**/Cargo.toml")?)
        .add(Glob::new("**/README.md")?)
        .add(Glob::new("*.bin")?)
        .build()?)
}

#[derive(clap::Parser)]
struct Cli {
    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(clap::Subcommand, Debug, Clone)]
enum Subcommand {
    /// Checks if a license is present in files that are not in the ignore list.
    CheckAll,
    /// Adds a license as needed to files that are not in the ignore list.
    AddAll,
}
