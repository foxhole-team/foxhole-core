use std::path::PathBuf;

pub(crate) const UPSTREAM_MARK: u32 = 0x2000_0000;
pub(crate) const TUNNEL_MARK: u32 = 0x4000_0000;
pub(crate) const PROOF_MARK: u32 = TUNNEL_MARK | 0x1000_0000;

pub(crate) fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Help,
    Capabilities,
    Check(PathBuf),
    Import {
        profile: PathBuf,
        output: PathBuf,
    },
    Run {
        config: PathBuf,
        state: PathBuf,
        interface: String,
    },
    Status(PathBuf),
    Probe {
        interface: String,
        state: PathBuf,
    },
    Bridge {
        interface: String,
        state: PathBuf,
        auth: PathBuf,
    },
    Owner {
        interface: String,
        state: PathBuf,
    },
}

pub(crate) fn parse(args: impl IntoIterator<Item = String>) -> Result<Command, &'static str> {
    let mut args = args.into_iter();
    let command = args.next().unwrap_or_else(|| "--help".into());
    if matches!(command.as_str(), "--help" | "-h" | "capabilities") {
        if args.next().is_some() {
            return Err("UNEXPECTED_ARGUMENT");
        }
        return Ok(if command == "capabilities" {
            Command::Capabilities
        } else {
            Command::Help
        });
    }
    if !matches!(
        command.as_str(),
        "check" | "run" | "status" | "probe" | "import" | "bridge" | "owner"
    ) {
        return Err("UNKNOWN_COMMAND");
    }
    let mut config = None;
    let mut state = None;
    let mut interface = None;
    let mut profile = None;
    let mut output = None;
    let mut auth = None;
    while let Some(flag) = args.next() {
        let target = match (command.as_str(), flag.as_str()) {
            ("check" | "run", "--config") => &mut config,
            ("run" | "status" | "probe" | "bridge" | "owner", "--state") => &mut state,
            ("run" | "probe" | "bridge" | "owner", "--interface") => &mut interface,
            ("bridge", "--auth") => &mut auth,
            ("import", "--profile") => &mut profile,
            ("import", "--out") => &mut output,
            _ => return Err("UNKNOWN_OPTION"),
        };
        let value = args.next().ok_or("MISSING_OPTION_VALUE")?;
        if value.is_empty()
            || value.len() > 4096
            || value.starts_with('-')
            || value.chars().any(char::is_control)
        {
            return Err("INVALID_OPTION_VALUE");
        }
        if target.replace(value).is_some() {
            return Err("DUPLICATE_OPTION");
        }
    }
    let interface = interface.unwrap_or_else(|| "foxhole0".into());
    if !valid_interface(&interface) {
        return Err("INVALID_INTERFACE");
    }
    match command.as_str() {
        "check" => Ok(Command::Check(config.ok_or("CONFIG_REQUIRED")?.into())),
        "status" => Ok(Command::Status(state.ok_or("STATE_REQUIRED")?.into())),
        "import" => {
            let profile = PathBuf::from(profile.ok_or("PROFILE_REQUIRED")?);
            let output = PathBuf::from(output.ok_or("OUTPUT_REQUIRED")?);
            if profile == output {
                return Err("PROFILE_OUTPUT_COLLISION");
            }
            Ok(Command::Import { profile, output })
        }
        "probe" => Ok(Command::Probe {
            interface,
            state: state.ok_or("STATE_REQUIRED")?.into(),
        }),
        "bridge" => Ok(Command::Bridge {
            interface,
            state: state.ok_or("STATE_REQUIRED")?.into(),
            auth: auth.ok_or("AUTH_REQUIRED")?.into(),
        }),
        "owner" => Ok(Command::Owner {
            interface,
            state: state.ok_or("STATE_REQUIRED")?.into(),
        }),
        "run" => {
            let config = PathBuf::from(config.ok_or("CONFIG_REQUIRED")?);
            let state = PathBuf::from(state.ok_or("STATE_REQUIRED")?);
            if config == state {
                return Err("CONFIG_STATE_COLLISION");
            }
            Ok(Command::Run {
                config,
                state,
                interface,
            })
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn command(args: &[&str]) -> Result<Command, &'static str> {
        parse(args.iter().map(|value| (*value).to_owned()))
    }

    #[test]
    fn import_uses_private_files_and_never_accepts_credentials_on_the_command_line() {
        assert_eq!(
            command(&[
                "import",
                "--profile",
                "/private/in",
                "--out",
                "/private/out"
            ]),
            Ok(Command::Import {
                profile: "/private/in".into(),
                output: "/private/out".into()
            })
        );
        assert!(command(&["import", "--link", "vless://synthetic"]).is_err());
        assert!(command(&["import", "--profile", "same", "--out", "same"]).is_err());
        assert!(command(&["import", "--profile", "in"]).is_err());
    }

    #[test]
    fn read_only_commands_do_not_require_privileged_configuration() {
        assert_eq!(command(&["capabilities"]), Ok(Command::Capabilities));
        assert_eq!(command(&["--help"]), Ok(Command::Help));
        assert_eq!(
            command(&["check", "--config", "/private/config.json"]),
            Ok(Command::Check("/private/config.json".into()))
        );
        assert_eq!(
            command(&["status", "--state", "/private/status.json"]),
            Ok(Command::Status("/private/status.json".into()))
        );
    }

    #[test]
    fn run_requires_explicit_private_paths_and_defaults_to_the_owned_tun() {
        assert_eq!(
            command(&[
                "run",
                "--config",
                "/private/config.json",
                "--state",
                "/private/status.json"
            ]),
            Ok(Command::Run {
                config: "/private/config.json".into(),
                state: "/private/status.json".into(),
                interface: "foxhole0".into()
            })
        );
        assert!(command(&["run", "--config", "/private/config.json"]).is_err());
        assert!(command(&["run", "--state", "/private/status.json"]).is_err());
    }

    #[test]
    fn interface_names_cannot_be_shell_or_ip_options_and_errors_never_echo_inputs() {
        for name in ["-4", "../tun", "tun;echo", "", "abcdefghijklmnop"] {
            let error = command(&[
                "probe",
                "--interface",
                name,
                "--state",
                "/private/status.json",
            ])
            .unwrap_err();
            assert!(!error.contains(name) || name.is_empty());
        }
        assert_eq!(
            command(&[
                "probe",
                "--interface",
                "foxhole0",
                "--state",
                "/private/status.json"
            ]),
            Ok(Command::Probe {
                interface: "foxhole0".into(),
                state: "/private/status.json".into()
            })
        );
    }

    #[test]
    fn duplicate_unknown_or_missing_options_are_refused_and_marks_remain_separate() {
        assert_ne!(UPSTREAM_MARK, TUNNEL_MARK);
        assert_eq!(PROOF_MARK & TUNNEL_MARK, TUNNEL_MARK);
        assert_eq!(PROOF_MARK & UPSTREAM_MARK, 0);
        assert_ne!(PROOF_MARK, TUNNEL_MARK);
        for args in [
            vec!["check", "--config"],
            vec!["check", "--config", "one", "--config", "two"],
            vec!["probe", "--config", "one"],
            vec!["probe", "--upstream-mark", "0x40000000"],
            vec!["capabilities", "extra"],
        ] {
            assert!(command(&args).is_err());
        }
    }

    #[test]
    fn bridge_credentials_are_private_file_inputs_only() {
        assert_eq!(
            command(&[
                "bridge",
                "--state",
                "/private/state",
                "--auth",
                "/private/auth"
            ]),
            Ok(Command::Bridge {
                interface: "foxhole0".into(),
                state: "/private/state".into(),
                auth: "/private/auth".into()
            })
        );
        assert!(command(&["bridge", "--state", "/private/state"]).is_err());
        assert!(
            command(&[
                "bridge",
                "--state",
                "/private/state",
                "--password",
                "secret"
            ])
            .is_err()
        );
    }
}
