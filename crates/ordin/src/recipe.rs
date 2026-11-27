// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Finding and reading the recipe, `ordin.toml`, for `ordin pack` and
//! `ordin lint`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use ordin_recipe::Recipe;

use crate::files;

/// The recipe read when no --manifest is given.
pub const DEFAULT_RECIPE: &str = "ordin.toml";

/// A recipe read, and where from.
#[derive(Debug)]
pub struct Used {
    /// The file.
    pub path: PathBuf,
    /// What it says.
    pub recipe: Recipe,
}

impl Used {
    /// The directory its paths are relative to.
    pub fn dir(&self) -> &Path {
        match self.path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir,
            _ => Path::new("."),
        }
    }
}

/// `path`, if there is anything there. Anything that stops it being
/// looked at is an error, so a recipe is never skipped because it
/// couldn't be seen.
fn default_recipe(path: &Path) -> Result<Option<PathBuf>> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(Some(path.to_path_buf())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| path.display().to_string()),
    }
}

/// Reads the recipe: `manifest`, or ./ordin.toml if there is one, unless
/// `none` (--no-manifest) is given.
///
/// # Errors
///
/// The recipe can't be read, isn't UTF-8 text, or is refused; the error
/// names the file, line and column.
pub fn read(manifest: Option<&Path>, none: bool) -> Result<Option<Used>> {
    if none {
        return Ok(None);
    }
    let path = match manifest {
        Some(path) => path.to_path_buf(),
        None => match default_recipe(Path::new(DEFAULT_RECIPE))? {
            Some(path) => path,
            None => return Ok(None),
        },
    };
    let max = u64::try_from(ordin_recipe::MAX_SIZE).unwrap_or(u64::MAX);
    let bytes = files::read_small(&path, max, "a recipe")?;
    let text = String::from_utf8(bytes)
        .map_err(|_| anyhow!("{}: a recipe is UTF-8 text", path.display()))?;
    let recipe = ordin_recipe::parse(&text).map_err(|e| anyhow!("{}:{e}", path.display()))?;
    Ok(Some(Used { path, recipe }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_recipe_is_skipped_only_when_there_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert_eq!(default_recipe(&file).unwrap(), Some(file.clone()));
        assert_eq!(default_recipe(&dir.path().join("none")).unwrap(), None);
        // A path that can't be looked at isn't taken for no recipe.
        let below = file.join("ordin.toml");
        let e = default_recipe(&below).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            format!("{}: Not a directory (os error 20)", below.display())
        );
    }
}
