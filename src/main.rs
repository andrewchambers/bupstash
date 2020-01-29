pub mod address;
pub mod chunk_storage;
pub mod chunker;
pub mod client;
pub mod crypto;
pub mod fsutil;
pub mod hex;
pub mod htree;
pub mod hydrogen;
pub mod keys;
pub mod protocol;
pub mod rollsum;
pub mod server;
pub mod store;
pub mod tquery;

use failure::Fail;
use getopts::{Matches, Options};

fn die(s: String) -> ! {
    eprintln!("{}", s);
    std::process::exit(1);
}

fn print_help_and_exit(subcommand: &str, opts: &Options) {
    let brief = match subcommand {
        "init" => include_str!("../doc/cli/init.txt"),
        "help" => include_str!("../doc/cli/help.txt"),
        "new-master-key" => include_str!("../doc/cli/new-master-key.txt"),
        "new-send-key" => include_str!("../doc/cli/new-send-key.txt"),
        _ => panic!(),
    };
    print!("{}", opts.usage(brief));
    std::process::exit(0);
}

fn default_cli_opts() -> Options {
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu.");
    opts
}

fn default_parse_opts(opts: Options, args: &[String]) -> Matches {
    if args.len() >= 2 && (args[1] == "-h" || args[1] == "--help") {
        print_help_and_exit(&args[0], &opts)
    }
    let matches = opts
        .parse(&args[1..])
        .unwrap_or_else(|e| die(e.to_string()));
    if matches.opt_present("h") {
        print_help_and_exit(&args[0], &opts)
    };
    matches
}

fn help_main(args: Vec<String>) -> Result<(), failure::Error> {
    let opts = default_cli_opts();
    print_help_and_exit(&args[0], &opts);
    Ok(())
}

fn init_main(args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();
    opts.optopt(
        "s",
        "storage",
        "The storage engine specification.",
        "STORAGE",
    );
    let matches = default_parse_opts(opts, &args[..]);

    if matches.free.len() != 1 {
        die("Expected a single path to initialize.".to_string());
    }

    let backend: store::StorageEngineSpec;

    if !matches.opt_present("storage") {
        backend = store::StorageEngineSpec::Local;
    } else {
        panic!("TODO")
    }

    store::Store::init(std::path::Path::new(&matches.free[0]), backend)
}

fn new_master_key_main(args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();
    opts.reqopt("o", "output", "set output file.", "PATH");
    let matches = default_parse_opts(opts, &args[..]);
    let master_key = keys::Key::MasterKeyV1(keys::MasterKey::gen());
    master_key.write_to_file(&matches.opt_str("o").unwrap())
}

fn new_send_key_main(args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();
    opts.reqopt("m", "master-key", "master key to derive key from.", "PATH");
    opts.reqopt("o", "output", "output file.", "PATH");
    let matches = default_parse_opts(opts, &args[..]);
    let k = keys::Key::load_from_file(&matches.opt_str("m").unwrap())?;
    match k {
        keys::Key::MasterKeyV1(master_key) => {
            let send_key = keys::Key::SendKeyV1(keys::SendKey::gen(&master_key));
            send_key.write_to_file(&matches.opt_str("o").unwrap())
        }
        _ => failure::bail!("key specified is not a master key"),
    }
}

fn search_main(args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();
    opts.reqopt("m", "master-key", "master key to derive key from.", "PATH");
    let matches = default_parse_opts(opts, &args[..]);
    let ast = match tquery::parse(&matches.free.join("•")) {
        Err(e) => {
            tquery::report_parse_error(e);
            std::process::exit(1);
        }
        Ok(ast) => ast,
    };
    eprintln!("{:?}", ast);
    Ok(())
}

fn send_main(args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();

    opts.optopt("k", "key", "Encryption key.", "PATH");
    opts.optopt("", "to", "URI of repository to save data info.", "URI");
    opts.optopt("f", "file", "Save a file.", "PATH");

    let matches = default_parse_opts(opts, &args[..]);

    let key = if matches.opt_present("to") {
        matches.opt_str("to").unwrap()
    } else if let Some(s) = std::env::var_os("ARCHIVIST_SEND_KEY") {
        s.into_string().unwrap()
    } else {
        failure::bail!("please set --key or the env var ARCHIVIST_SEND_KEY");
    };

    let key = keys::Key::load_from_file(&key)?;

    let to = if matches.opt_present("to") {
        matches.opt_str("to").unwrap()
    } else if let Some(s) = std::env::var_os("ARCHIVIST_SEND_TO_URI") {
        s.into_string().unwrap()
    } else {
        failure::bail!("please set --to or the env var ARCHIVIST_SEND_TO_URI");
    };

    let _encrypt_ctx = crypto::EncryptContext::new(&key);

    let mut serve_cmd_args = if to.starts_with('/') {
        vec!["archivist".to_owned(), "serve".to_owned(), to]
    } else if to.starts_with("ssh://") {
        let u = url::Url::parse(&to)?;

        let mut args = vec!["ssh".to_owned()];

        if !u.username().len() != 0 {
            args.push("-o".to_owned());
            args.push("User=".to_owned() + &u.username().to_string());
        };
        if let Some(p) = u.port() {
            args.push("-o".to_owned());
            args.push("Port=".to_owned() + &p.to_string());
        };
        match u.host() {
            Some(h) => args.push(h.to_string()),
            None => failure::bail!("'to' ssh uri does not have a valid host"),
        };

        args.push("--".to_owned());
        args.push("archivist".to_owned());
        args.push("serve".to_owned());
        args.push(u.path().to_owned());
        args
    } else {
        failure::bail!("don't understand 'to' respository uri: {:?}", to);
    };

    let bin = serve_cmd_args.remove(0);
    let mut serve_proc = match std::process::Command::new(bin)
        .args(serve_cmd_args)
        .stderr(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::piped())
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(err) => return Err(err.context("error spawning remote serve command").into()),
    };

    let _serve_out = serve_proc.stdout.as_mut();
    let _serve_in = serve_proc.stdin.as_mut();

    Ok(())
}

fn serve_main(args: Vec<String>) -> Result<(), failure::Error> {
    let opts = default_cli_opts();
    let matches = default_parse_opts(opts, &args[..]);

    if matches.free.len() != 1 {
        die("Expected a single path to initialize.".to_string());
    }

    server::serve(
        server::ServerConfig {
            store_path: std::path::Path::new(&matches.free[0]).to_path_buf(),
        },
        &mut std::io::stdin(),
        &mut std::io::stdout(),
    )?;

    Ok(())
}

fn main() {
    unsafe { hydrogen::init() };

    let mut args: Vec<String> = std::env::args().collect();
    let program = args[0].clone();
    args.remove(0);
    if args.is_empty() {
        die(format!(
            "Expected at least a single subcommand, try '{} help'.",
            program
        ))
    }
    let subcommand = args[0].clone();

    let result = match subcommand.as_str() {
        "init" => init_main(args),
        "new-master-key" => new_master_key_main(args),
        "new-send-key" => new_send_key_main(args),
        "search" => search_main(args),
        "send" => send_main(args),
        "serve" => serve_main(args),
        "help" | "--help" | "-h" => {
            args[0] = "help".to_string();
            help_main(args)
        }
        _ => die(format!(
            "Unknown subcommand '{}', try  '{} help'.",
            subcommand, program
        )),
    };

    if let Err(err) = result {
        die(format!("archivist {}: {}", subcommand, err));
    }
}
