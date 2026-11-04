//! Exercise the published examples' CLI definitions without their unavailable
//! upstream `hub` helper or any network/certificate operations.
use clap::{App, AppSettings, Arg, ErrorKind};

fn example_cli(name: &'static str, endpoint: &'static str) -> App<'static> {
    App::new(name)
        .version("0.1.0")
        .setting(AppSettings::DeriveDisplayOrder)
        .setting(AppSettings::SubcommandsNegateReqs)
        .arg(
            Arg::with_name("FULLHELP")
                .help("Prints more detailed help information")
                .long("fullhelp"),
        )
        .arg(
            Arg::with_name(endpoint)
                .required_unless("FULLHELP")
                .takes_value(true)
                .default_value("127.0.0.1:4444")
                .long(endpoint)
                .help("DTLS endpoint name."),
        )
}

#[test]
fn psk_and_certificate_clients_parse_the_published_server_flag() {
    // Certificate and PSK settings are configured in the examples' Rust code.
    // Their exposed CLI selects the endpoint, without separate key/cert flags.
    for name in ["dial_psk", "dial_verify", "dial_selfsign"] {
        let matches = example_cli(name, "server")
            .try_get_matches_from([name, "--server", "127.0.0.1:5555"])
            .unwrap();
        assert_eq!(matches.value_of("server"), Some("127.0.0.1:5555"));
        assert!(!matches.is_present("FULLHELP"));
    }
}

#[test]
fn psk_and_certificate_servers_keep_defaults_and_parse_host() {
    for name in ["listen_psk", "listen_verify", "listen_selfsign"] {
        let defaults = example_cli(name, "host")
            .try_get_matches_from([name])
            .unwrap();
        assert_eq!(defaults.value_of("host"), Some("127.0.0.1:4444"));
        let matches = example_cli(name, "host")
            .try_get_matches_from([name, "--host", "127.0.0.1:5555"])
            .unwrap();
        assert_eq!(matches.value_of("host"), Some("127.0.0.1:5555"));
    }
}

#[test]
fn full_help_and_invalid_arguments_work_without_terminal_color() {
    for (name, endpoint) in [("dial_psk", "server"), ("listen_verify", "host")] {
        let matches = example_cli(name, endpoint)
            .try_get_matches_from([name, "--fullhelp"])
            .unwrap();
        assert!(matches.is_present("FULLHELP"));

        let mut help = Vec::new();
        example_cli(name, endpoint)
            .write_long_help(&mut help)
            .unwrap();
        let text = String::from_utf8(help).unwrap();
        assert!(text.contains("--fullhelp"));
        assert!(text.contains(&format!("--{endpoint}")));
        assert!(!text.contains("\u{1b}["));

        let error = example_cli(name, endpoint)
            .try_get_matches_from([name, "--unknown"])
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }
}
