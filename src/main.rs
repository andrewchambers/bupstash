pub mod address;
pub mod chunk_storage;
pub mod chunker;
pub mod crypto;
pub mod fsutil;
pub mod hex;
pub mod htree;
pub mod hydrogen;
pub mod keys;
pub mod rollsum;
pub mod store;
pub mod tquery;

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
    opts.optflag("h", "help", "print this help menu");
    opts
}

fn default_parse_opts(opts: Options, args: &[String]) -> Matches {
    if args[1] == "-h" || args[1] == "--help" {
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
        "The storage engine specification, default.",
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
        die(format!("Error during command: {}", err));
    }
}
