#![feature(test)]
extern crate test;

pub mod address;
pub mod chunk_storage;
pub mod chunker;
pub mod client;
pub mod crypto;
pub mod fsutil;
pub mod hex;
pub mod htree;
pub mod hydrogen;
pub mod itemset;
pub mod keys;
pub mod protocol;
pub mod querycache;
pub mod repository;
pub mod rollsum;
pub mod sendlog;
pub mod server;
pub mod tquery;

use failure::Fail;
use getopts::{Matches, Options};
use std::collections::HashMap;

fn die(s: String) -> ! {
    eprintln!("{}", s);
    std::process::exit(1);
}

fn cache_dir() -> Result<std::path::PathBuf, failure::Error> {
    let mut cache_dir = match std::env::var_os("XDG_CACHE_HOME") {
        Some(cache_dir) => std::path::PathBuf::from(&cache_dir),
        None => match std::env::var_os("HOME") {
            Some(home) => {
                let mut h = std::path::PathBuf::from(&home);
                h.push(".cache");
                h
            }
            None => failure::bail!("unable to determine cache dir from XDG_CACHE_HOME or HOME"),
        },
    };
    cache_dir.push("archivist");
    Ok(cache_dir)
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

    let backend: repository::StorageEngineSpec;

    if !matches.opt_present("storage") {
        backend = repository::StorageEngineSpec::Local;
    } else {
        panic!("TODO")
    }

    repository::Repo::init(std::path::Path::new(&matches.free[0]), backend)
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

fn matches_to_serve_process(matches: &Matches) -> Result<std::process::Child, failure::Error> {
    let repo = if matches.opt_present("repository") {
        matches.opt_str("repository").unwrap()
    } else if let Some(s) = std::env::var_os("ARCHIVIST_REPOSITORY") {
        s.into_string().unwrap()
    } else {
        failure::bail!("please set --respository or the env var ARCHIVIST_REPOSITORY");
    };

    let mut serve_cmd_args = if repo.starts_with("ssh://") {
        let re = regex::Regex::new(r"^ssh://(?:([a-zA-Z0-9]+)@)?([^/]*)(.*)$")?;
        let caps = re.captures(&repo).unwrap();

        let mut args = vec!["ssh".to_owned()];

        if let Some(user) = caps.get(1) {
            args.push("-o".to_owned());
            args.push("User=".to_owned() + user.as_str());
        }
        args.push(caps[2].to_string());
        args.push("--".to_owned());
        args.push("archivist".to_owned());
        args.push("serve".to_owned());
        let repo_path = caps[3].to_string();
        if repo_path.len() != 0 {
            args.push(repo_path);
        }
        args
    } else {
        vec!["archivist".to_owned(), "serve".to_owned(), repo.to_string()]
    };

    let bin = serve_cmd_args.remove(0);
    let serve_proc = match std::process::Command::new(bin)
        .args(serve_cmd_args)
        .stderr(std::process::Stdio::inherit())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(err) => return Err(err.context("error spawning serve command").into()),
    };

    Ok(serve_proc)
}

fn list_main(args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();
    opts.optopt(
        "r",
        "repository",
        "URI of repository to list items from.",
        "REPO",
    );
    opts.reqopt(
        "k",
        "key",
        "master key to decrypt items during listing/search.",
        "PATH",
    );
    opts.optopt(
        "",
        "query-cache",
        "Path to the query cache (used for storing synced items before search).",
        "PATH",
    );
    let matches = default_parse_opts(opts, &args[..]);

    let key = if matches.opt_present("key") {
        matches.opt_str("key").unwrap()
    } else if let Some(s) = std::env::var_os("ARCHIVIST_MASTER_KEY") {
        s.into_string().unwrap()
    } else {
        failure::bail!("please set --key or the env var ARCHIVIST_MASTER_KEY");
    };

    let key = keys::Key::load_from_file(&key)?;

    let key = match key {
        keys::Key::MasterKeyV1(mk) => mk,
        _ => failure::bail!("the provided key is a not a master decryption key"),
    };

    let mut query: Option<tquery::Query> = None;

    if matches.free.len() != 0 {
        query = match tquery::parse(&matches.free.join("•")) {
            Err(e) => {
                tquery::report_parse_error(e);
                std::process::exit(1);
            }
            Ok(query) => Some(query),
        };
    }

    let mut query_cache = match matches.opt_str("query-cache") {
        Some(query_cache) => querycache::QueryCache::open(&std::path::PathBuf::from(query_cache))?,
        None => match std::env::var_os("ARCHIVIST_QUERY_CACHE") {
            Some(query_cache) => {
                querycache::QueryCache::open(&std::path::PathBuf::from(query_cache))?
            }
            None => {
                let mut p = cache_dir()?;
                std::fs::create_dir_all(&p)?;
                p.push("query-cache.sqlite3");
                querycache::QueryCache::open(&p)?
            }
        },
    };

    let warned_wrong_key = &mut false;
    let mut f = |id: i64, metadata: itemset::ItemMetadata| {
        if metadata.encrypt_header.master_key_id() != key.id {
            if !*warned_wrong_key {
                *warned_wrong_key = true;
                eprintln!("NOTE: Search skipping items encrypted with different master key.")
            }
            return Ok(());
        }

        let mut ctx = crypto::DecryptContext::open(&key, &metadata.encrypt_header)?;
        let tags = ctx.decrypt_data(
            &metadata.encrypted_tags, /* XXX copying here seems pointless */
        )?;

        let tags: HashMap<String, Option<String>> = bincode::deserialize(&tags)?;

        let doprint = match query {
            Some(ref query) => tquery::query_matches(query, &tags),
            None => true,
        };

        if doprint {
            println!("{}: {:?}", id, tags);
        }

        Ok(())
    };

    let mut serve_proc = matches_to_serve_process(&matches)?;
    let mut serve_out = serve_proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.stdin.as_mut().unwrap();

    client::list(&mut query_cache, &mut f, &mut serve_out, &mut serve_in)?;

    Ok(())
}

fn send_main(args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();

    opts.optopt("k", "key", "Encryption key.", "PATH");
    opts.optopt(
        "r",
        "repository",
        "URI of repository to save data info.",
        "REPO",
    );
    opts.optopt("f", "file", "Save a file.", "PATH");
    opts.optflag(
        "",
        "no-compression",
        "Disable compression (Use for for already compressed/encrypted data).",
    );
    opts.optopt(
        "",
        "send-log",
        "Use send log to avoid resending data that was sent previously.",
        "PATH",
    );

    let matches = default_parse_opts(opts, &args[..]);

    let key = if matches.opt_present("key") {
        matches.opt_str("key").unwrap()
    } else if let Some(s) = std::env::var_os("ARCHIVIST_SEND_KEY") {
        s.into_string().unwrap()
    } else {
        failure::bail!("please set --key or the env var ARCHIVIST_SEND_KEY");
    };

    let key = keys::Key::load_from_file(&key)?;

    let mut data = if matches.opt_present("file") {
        let f = matches.opt_str("file").unwrap();
        let f = std::fs::File::open(f)?;
        f
    } else {
        failure::bail!("please set --file to the data you are sending")
    };

    let mut tags = HashMap::<String, Option<String>>::new();

    let tag_re = regex::Regex::new(r"^([^=]+)(?:=(.+))?$")?;
    for a in &matches.free {
        match tag_re.captures(&a) {
            Some(caps) => {
                let t = &caps[1];
                let v = caps.get(2);
                match v {
                    Some(v) => tags.insert(t.to_string(), Some(v.as_str().to_string())),
                    None => tags.insert(t.to_string(), None),
                };
            }
            None => failure::bail!("argument '{}' is not a valid tag value.", a),
        }
    }

    let encrypt_ctx = crypto::EncryptContext::new(&key);

    let mut send_log = match matches.opt_str("send-log") {
        Some(send_log) => sendlog::SendLog::open(&std::path::PathBuf::from(send_log))?,
        None => match std::env::var_os("ARCHIVIST_SEND_LOG") {
            Some(send_log) => sendlog::SendLog::open(&std::path::PathBuf::from(send_log))?,
            None => {
                let mut p = cache_dir()?;
                std::fs::create_dir_all(&p)?;
                p.push("send-log.sqlite3");
                sendlog::SendLog::open(&p)?
            }
        },
    };

    let mut serve_proc = matches_to_serve_process(&matches)?;
    let mut serve_out = serve_proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.stdin.as_mut().unwrap();

    let id = client::send(
        client::SendOptions {
            compression: !matches.opt_present("no-compression"),
        },
        &encrypt_ctx,
        &mut send_log,
        &mut serve_out,
        &mut serve_in,
        &tags,
        &mut data,
    )?;

    println!("{}", id);
    Ok(())
}

fn get_main(args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();

    opts.optopt("k", "key", "Decryption key.", "PATH");
    opts.optopt(
        "r",
        "repository",
        "URI of repository to fetch data from.",
        "REPO",
    );
    opts.optopt("", "id", "ID of entry to fetch.", "ID");

    let matches = default_parse_opts(opts, &args[..]);

    let key = if matches.opt_present("key") {
        matches.opt_str("key").unwrap()
    } else if let Some(s) = std::env::var_os("ARCHIVIST_MASTER_KEY") {
        s.into_string().unwrap()
    } else {
        failure::bail!("please set --key or the env var ARCHIVIST_MASTER_KEY");
    };

    let key = keys::Key::load_from_file(&key)?;

    let key = match key {
        keys::Key::MasterKeyV1(mk) => mk,
        _ => failure::bail!("the provided key is a not a master decryption key"),
    };

    let id = if matches.opt_present("id") {
        let id_str = matches.opt_str("id").unwrap();
        match id_str.parse::<i64>() {
            Ok(addr) => addr,
            Err(err) => return Err(err.context("--id invalid").into()),
        }
    } else {
        failure::bail!("please set or --id.")
    };

    let mut serve_proc = matches_to_serve_process(&matches)?;
    let mut serve_out = serve_proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.stdin.as_mut().unwrap();

    client::request_data_stream(
        &key,
        id,
        &mut serve_out,
        &mut serve_in,
        &mut std::io::stdout(),
    )?;

    Ok(())
}

fn remove_main(args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();

    opts.optopt(
        "r",
        "repository",
        "URI of repository to fetch data from.",
        "REPO",
    );
    opts.optopt("", "id", "ID of entry to delete.", "ID");

    let matches = default_parse_opts(opts, &args[..]);

    let id = if matches.opt_present("id") {
        let id_str = matches.opt_str("id").unwrap();
        match id_str.parse::<i64>() {
            Ok(addr) => addr,
            Err(err) => return Err(err.context("--id invalid").into()),
        }
    } else {
        failure::bail!("please set or --id.")
    };

    let mut serve_proc = matches_to_serve_process(&matches)?;
    let mut serve_out = serve_proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.stdin.as_mut().unwrap();

    client::remove(vec![id], &mut serve_out, &mut serve_in)?;

    Ok(())
}

fn gc_main(args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();
    opts.optopt(
        "r",
        "repository",
        "URI of repository to run the garbage collector upon.",
        "REPO",
    );
    let matches = default_parse_opts(opts, &args[..]);

    let mut serve_proc = matches_to_serve_process(&matches)?;
    let mut serve_out = serve_proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.stdin.as_mut().unwrap();
    // XXX TODO more gc stats.
    // Especially interested in repository size and also
    // how much space was freed.
    let stats = client::gc(&mut serve_out, &mut serve_in)?;
    println!("{:?} chunks deleted", stats.chunks_deleted);
    println!("{:?} bytes freed", stats.bytes_freed);
    println!("{:?} bytes remaining", stats.bytes_remaining);
    Ok(())
}

fn serve_main(args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();
    opts.optflag(
        "",
        "allow-add",
        "allow client to add more entry to the repository.",
    );
    opts.optflag(
        "",
        "allow-edit",
        "allow client to edit and remove repository entries.",
    );
    opts.optflag(
        "",
        "allow-gc",
        "allow client to run the repository garbage collector.",
    );
    opts.optflag(
        "",
        "allow-read",
        "allow client to read and query the repository.",
    );
    let matches = default_parse_opts(opts, &args[..]);

    if matches.free.len() != 1 {
        die("Expected a single path to initialize.".to_string());
    }

    let mut allow_add = true;
    let mut allow_edit = true;
    let mut allow_gc = true;
    let mut allow_read = true;

    if matches.opt_present("allow-add")
        || matches.opt_present("allow-edit")
        || matches.opt_present("allow-gc")
        || matches.opt_present("allow-read")
    {
        allow_add = matches.opt_present("allow-add");
        allow_edit = matches.opt_present("allow-edit");
        allow_gc = matches.opt_present("allow-gc");
        allow_read = matches.opt_present("allow-read");
    }

    server::serve(
        server::ServerConfig {
            allow_add,
            allow_edit,
            allow_gc,
            allow_read,
            repo_path: std::path::Path::new(&matches.free[0]).to_path_buf(),
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
        "list" => list_main(args),
        "send" => send_main(args),
        "get" => get_main(args),
        "gc" => gc_main(args),
        "remove" | "rm" => remove_main(args),
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
