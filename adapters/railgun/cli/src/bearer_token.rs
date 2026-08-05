//! Bearer-token sourcing for the production serve paths.
//!
//! Exactly one of the inline config field, a token file, or the environment may
//! resolve. Any file that carries the token must be unreadable to group and
//! other, checked before the process serves anything.

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Environment variable consulted when neither config field is set.
pub const BEARER_TOKEN_ENV: &str = "RAVEN_BEARER_TOKEN";

/// Placeholder shipped in the example config; never a usable token.
pub const PLACEHOLDER_TOKEN: &str = "REPLACE_ME";

/// Which surface supplied the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSource {
    /// `[global].token` in the config file.
    Inline,
    /// The file named by `[global].token_file`.
    File,
    /// The [`BEARER_TOKEN_ENV`] environment variable.
    Env,
}

impl TokenSource {
    /// Operator-facing name, as written in the config or shell.
    pub fn label(self) -> &'static str {
        match self {
            Self::Inline => "[global].token",
            Self::File => "[global].token_file",
            Self::Env => BEARER_TOKEN_ENV,
        }
    }
}

/// A resolved token and the surface it came from.
#[derive(Debug, Clone)]
pub struct ResolvedBearerToken {
    /// The token, whitespace-trimmed.
    pub token: String,
    /// Where it was read from.
    pub source: TokenSource,
}

/// Failure resolving or permission-checking the bearer token.
#[derive(Debug, Error)]
pub enum BearerTokenError {
    /// Nothing supplied a token.
    #[error(
        "no bearer token: set exactly one of [global].token, [global].token_file, or the \
         {env} environment variable (config: {config})"
    )]
    NoSource {
        /// Config file that was read.
        config: PathBuf,
        /// Name of the environment variable that was consulted.
        env: &'static str,
    },
    /// More than one surface supplied a token.
    #[error(
        "ambiguous bearer token: {sources} are all set (config: {config}); leave exactly one \
         so the serving token is unambiguous"
    )]
    MultipleSources {
        /// Config file that was read.
        config: PathBuf,
        /// Comma-separated labels of every source that resolved.
        sources: String,
    },
    /// A surface was present but carried nothing usable.
    #[error("{source_label} is set but empty after trimming whitespace (config: {config})")]
    Empty {
        /// Config file that was read.
        config: PathBuf,
        /// Label of the empty source.
        source_label: &'static str,
    },
    /// The token file could not be read.
    #[error("read [global].token_file {path}: {source}")]
    ReadTokenFile {
        /// Path that failed to read.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// A file carrying the token is reachable by group or other.
    #[error(
        "{path} is mode {mode:04o} and carries {carries}; group and other can read it. \
         Run `chmod 600 {path}` and re-run, or move the token into a 600-mode file \
         referenced by [global].token_file"
    )]
    Permissions {
        /// The over-permissive file.
        path: PathBuf,
        /// Permission bits found, as reported by `st_mode & 0o7777`.
        mode: u32,
        /// What the file holds, for the operator reading the message.
        carries: &'static str,
    },
    /// The example-config placeholder reached the serving path.
    #[error(
        "{source_label} is the literal placeholder {placeholder:?} from the example config \
         (config: {config}). Replace it with at least 16 bytes of operator-private entropy \
         (e.g. `openssl rand -hex 32`) before serving"
    )]
    Placeholder {
        /// Config file that was read.
        config: PathBuf,
        /// Label of the source that carried the placeholder.
        source_label: &'static str,
        /// The rejected literal.
        placeholder: &'static str,
    },
}

/// Resolve the bearer token from exactly one surface, permission-gating any file that carries it.
///
/// `env_token` is passed in rather than read here so callers can test the
/// precedence rules without mutating process environment.
///
/// # Errors
/// Zero or multiple sources, an empty source, an unreadable token file, a
/// group- or world-reachable file carrying the token, or the example placeholder.
pub fn resolve_bearer_token(
    inline: Option<&str>,
    token_file: Option<&Path>,
    env_token: Option<String>,
    config_path: &Path,
) -> Result<ResolvedBearerToken, BearerTokenError> {
    let (source, raw) = match (inline, token_file, env_token) {
        (Some(literal), None, None) => {
            ensure_secret_file_mode(config_path, "an inline [global].token")?;
            (TokenSource::Inline, literal.to_owned())
        }
        (None, Some(path), None) => {
            ensure_secret_file_mode(path, "the bearer token")?;
            let body = std::fs::read_to_string(path).map_err(|source| {
                BearerTokenError::ReadTokenFile {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            (TokenSource::File, body)
        }
        (None, None, Some(from_env)) => (TokenSource::Env, from_env),
        (None, None, None) => {
            return Err(BearerTokenError::NoSource {
                config: config_path.to_path_buf(),
                env: BEARER_TOKEN_ENV,
            })
        }
        (seen_inline, seen_file, seen_env) => {
            let mut sources: Vec<&'static str> = Vec::with_capacity(3);
            if seen_inline.is_some() {
                sources.push(TokenSource::Inline.label());
            }
            if seen_file.is_some() {
                sources.push(TokenSource::File.label());
            }
            if seen_env.is_some() {
                sources.push(TokenSource::Env.label());
            }
            return Err(BearerTokenError::MultipleSources {
                config: config_path.to_path_buf(),
                sources: sources.join(", "),
            });
        }
    };

    let token = raw.trim().to_owned();
    if token.is_empty() {
        return Err(BearerTokenError::Empty {
            config: config_path.to_path_buf(),
            source_label: source.label(),
        });
    }
    if token == PLACEHOLDER_TOKEN {
        return Err(BearerTokenError::Placeholder {
            config: config_path.to_path_buf(),
            source_label: source.label(),
            placeholder: PLACEHOLDER_TOKEN,
        });
    }

    Ok(ResolvedBearerToken { token, source })
}

/// Refuse any group- or other-reachable mode on a file that carries the token.
///
/// # Errors
/// [`BearerTokenError::Permissions`] when any of the low six mode bits is set.
/// A stat failure is not fatal here: the read that follows reports it with a
/// path, and an unreadable file cannot leak.
#[cfg(unix)]
pub fn ensure_secret_file_mode(path: &Path, carries: &'static str) -> Result<(), BearerTokenError> {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(());
    };
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(BearerTokenError::Permissions {
            path: path.to_path_buf(),
            mode,
            carries,
        });
    }
    Ok(())
}

/// No-op off unix: the mode bits this gate reads do not exist there.
#[cfg(not(unix))]
pub fn ensure_secret_file_mode(
    _path: &Path,
    _carries: &'static str,
) -> Result<(), BearerTokenError> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn write_mode(dir: &Path, name: &str, body: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, body).expect("write fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod fixture");
        path
    }

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn inline_token_from_a_600_config_resolves() {
        let dir = tempdir();
        let config = write_mode(dir.path(), "mainnet.toml", "", 0o600);
        let resolved = resolve_bearer_token(Some("inline-token-long-enough"), None, None, &config)
            .expect("single source on a 600 config");
        assert_eq!(resolved.source, TokenSource::Inline);
        assert_eq!(resolved.token, "inline-token-long-enough");
    }

    #[test]
    fn inline_token_in_a_644_config_refuses_to_boot() {
        let dir = tempdir();
        let config = write_mode(dir.path(), "mainnet.toml", "", 0o644);
        let err = resolve_bearer_token(Some("inline-token-long-enough"), None, None, &config)
            .expect_err("world-readable config carrying a token must be rejected");
        let rendered = err.to_string();
        assert!(matches!(
            err,
            BearerTokenError::Permissions { mode: 0o644, .. }
        ));
        assert!(rendered.contains("mainnet.toml"), "{rendered}");
        assert!(rendered.contains("0644"), "{rendered}");
        assert!(rendered.contains("chmod 600"), "{rendered}");
    }

    #[test]
    fn a_644_config_is_fine_when_the_token_lives_in_a_600_file() {
        let dir = tempdir();
        let config = write_mode(dir.path(), "mainnet.toml", "", 0o644);
        let token_file = write_mode(
            dir.path(),
            "bearer-token",
            "file-token-long-enough\n",
            0o600,
        );
        let resolved = resolve_bearer_token(None, Some(&token_file), None, &config)
            .expect("the config no longer carries the secret");
        assert_eq!(resolved.source, TokenSource::File);
        assert_eq!(resolved.token, "file-token-long-enough");
    }

    #[test]
    fn a_group_readable_token_file_refuses_to_boot() {
        let dir = tempdir();
        let config = write_mode(dir.path(), "mainnet.toml", "", 0o600);
        let token_file = write_mode(dir.path(), "bearer-token", "file-token-long-enough", 0o640);
        let err = resolve_bearer_token(None, Some(&token_file), None, &config)
            .expect_err("group-readable token file must be rejected");
        assert!(matches!(
            err,
            BearerTokenError::Permissions { mode: 0o640, .. }
        ));
        assert!(err.to_string().contains("bearer-token"), "{err}");
    }

    #[test]
    fn env_resolves_when_neither_config_field_is_set() {
        let dir = tempdir();
        let config = write_mode(dir.path(), "mainnet.toml", "", 0o644);
        let resolved = resolve_bearer_token(
            None,
            None,
            Some("  env-token-long-enough  ".to_owned()),
            &config,
        )
        .expect("env is the only source");
        assert_eq!(resolved.source, TokenSource::Env);
        assert_eq!(resolved.token, "env-token-long-enough");
    }

    #[test]
    fn zero_sources_names_all_three() {
        let dir = tempdir();
        let config = write_mode(dir.path(), "mainnet.toml", "", 0o600);
        let err = resolve_bearer_token(None, None, None, &config).expect_err("no source");
        let rendered = err.to_string();
        assert!(matches!(err, BearerTokenError::NoSource { .. }));
        assert!(rendered.contains("[global].token"), "{rendered}");
        assert!(rendered.contains("[global].token_file"), "{rendered}");
        assert!(rendered.contains(BEARER_TOKEN_ENV), "{rendered}");
    }

    #[test]
    fn two_sources_name_exactly_the_ones_seen() {
        let dir = tempdir();
        let config = write_mode(dir.path(), "mainnet.toml", "", 0o600);
        let token_file = write_mode(dir.path(), "bearer-token", "file-token", 0o600);
        let err = resolve_bearer_token(Some("inline-token"), Some(&token_file), None, &config)
            .expect_err("two sources");
        let rendered = err.to_string();
        assert!(matches!(err, BearerTokenError::MultipleSources { .. }));
        assert!(rendered.contains("[global].token,"), "{rendered}");
        assert!(rendered.contains("[global].token_file"), "{rendered}");
        assert!(!rendered.contains(BEARER_TOKEN_ENV), "{rendered}");
    }

    #[test]
    fn three_sources_name_all_of_them() {
        let dir = tempdir();
        let config = write_mode(dir.path(), "mainnet.toml", "", 0o600);
        let token_file = write_mode(dir.path(), "bearer-token", "file-token", 0o600);
        let err = resolve_bearer_token(
            Some("inline-token"),
            Some(&token_file),
            Some("env-token".to_owned()),
            &config,
        )
        .expect_err("three sources");
        let rendered = err.to_string();
        assert!(rendered.contains(BEARER_TOKEN_ENV), "{rendered}");
    }

    #[test]
    fn an_empty_source_is_not_silently_accepted() {
        let dir = tempdir();
        let config = write_mode(dir.path(), "mainnet.toml", "", 0o600);
        let token_file = write_mode(dir.path(), "bearer-token", "   \n", 0o600);
        let err = resolve_bearer_token(None, Some(&token_file), None, &config)
            .expect_err("whitespace-only token file");
        assert!(matches!(
            err,
            BearerTokenError::Empty {
                source_label: "[global].token_file",
                ..
            }
        ));
    }

    #[test]
    fn a_missing_token_file_reports_its_path() {
        let dir = tempdir();
        let config = write_mode(dir.path(), "mainnet.toml", "", 0o600);
        let missing = dir.path().join("absent-token");
        let err = resolve_bearer_token(None, Some(&missing), None, &config)
            .expect_err("missing token file");
        assert!(matches!(err, BearerTokenError::ReadTokenFile { .. }));
        assert!(err.to_string().contains("absent-token"), "{err}");
    }

    #[test]
    fn the_placeholder_is_rejected_from_every_source() {
        let dir = tempdir();
        let config = write_mode(dir.path(), "mainnet.toml", "", 0o600);
        let inline = resolve_bearer_token(Some(PLACEHOLDER_TOKEN), None, None, &config)
            .expect_err("inline placeholder");
        assert!(matches!(inline, BearerTokenError::Placeholder { .. }));

        let token_file = write_mode(dir.path(), "bearer-token", PLACEHOLDER_TOKEN, 0o600);
        let from_file = resolve_bearer_token(None, Some(&token_file), None, &config)
            .expect_err("token-file placeholder");
        assert!(matches!(from_file, BearerTokenError::Placeholder { .. }));

        let from_env =
            resolve_bearer_token(None, None, Some(PLACEHOLDER_TOKEN.to_owned()), &config)
                .expect_err("env placeholder");
        assert!(matches!(from_env, BearerTokenError::Placeholder { .. }));
    }
}
