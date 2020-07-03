pub mod address;
pub mod chunk_storage;
pub mod chunker;
pub mod client;
pub mod crypto;
pub mod external_chunk_storage;
pub mod fsutil;
pub mod hex;
pub mod htree;
pub mod itemset;
pub mod keys;
pub mod local_chunk_storage;
pub mod protocol;
pub mod querycache;
pub mod repository;
pub mod rollsum;
pub mod sendlog;
pub mod server;
pub mod tquery;

use failure::Fail;
use getopts::{Matches, Options};
use std::collections::BTreeMap;

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
    opts.parsing_style(getopts::ParsingStyle::StopAtFirstFree);
    opts.optflag("h", "help", "print this help menu.");
    opts
}

fn query_cache_opt(opts: &mut Options) {
    opts.optopt(
        "",
        "query-cache",
        "Path to the query cache (used for storing synced items before search).",
        "PATH",
    );
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
        failure::bail!("Expected a single path to initialize.");
    }

    let backend: repository::StorageEngineSpec = match matches.opt_str("storage") {
        Some(s) => match serde_json::from_str(&s) {
            Ok(s) => s,
            Err(err) => failure::bail!("unable to parse storage engine spec: {}", err),
        },
        None => repository::StorageEngineSpec::Local,
    };

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
    opts.reqopt(
        "m",
        "master-key",
        "master key to derive send key from.",
        "PATH",
    );
    opts.reqopt("o", "output", "output file.", "PATH");
    let matches = default_parse_opts(opts, &args[..]);
    let k = keys::Key::load_from_file(&matches.opt_str("m").unwrap())?;
    match k {
        keys::Key::MasterKeyV1(master_key) => {
            let send_key = keys::Key::SendKeyV1(keys::SendKey::gen(&master_key));
            send_key.write_to_file(&matches.opt_str("o").unwrap())
        }
        _ => failure::bail!("key is not a master key"),
    }
}

fn new_metadata_key_main(args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();
    opts.reqopt(
        "m",
        "master-key",
        "master key to derive metadata key from.",
        "PATH",
    );
    opts.reqopt("o", "output", "output file.", "PATH");
    let matches = default_parse_opts(opts, &args[..]);
    let k = keys::Key::load_from_file(&matches.opt_str("m").unwrap())?;
    match k {
        keys::Key::MasterKeyV1(master_key) => {
            let send_key = keys::Key::MetadataKeyV1(keys::MetadataKey::gen(&master_key));
            send_key.write_to_file(&matches.opt_str("o").unwrap())
        }
        _ => failure::bail!("key is not a master key"),
    }
}

fn matches_to_query_cache(matches: &Matches) -> Result<querycache::QueryCache, failure::Error> {
    match matches.opt_str("query-cache") {
        Some(query_cache) => querycache::QueryCache::open(&std::path::PathBuf::from(query_cache)),
        None => match std::env::var_os("ARCHIVIST_QUERY_CACHE") {
            Some(query_cache) => {
                querycache::QueryCache::open(&std::path::PathBuf::from(query_cache))
            }
            None => {
                let mut p = cache_dir()?;
                std::fs::create_dir_all(&p)?;
                p.push("query-cache.sqlite3");
                querycache::QueryCache::open(&p)
            }
        },
    }
}

fn matches_to_send_log(matches: &Matches) -> Result<sendlog::SendLog, failure::Error> {
    // TODO XXX make cli option/env
    const SEND_SEQUENCE_MEMORY: i64 = 3;
    match matches.opt_str("send-log") {
        Some(send_log) => {
            sendlog::SendLog::open(&std::path::PathBuf::from(send_log), SEND_SEQUENCE_MEMORY)
        }
        None => match std::env::var_os("ARCHIVIST_SEND_LOG") {
            Some(send_log) => {
                sendlog::SendLog::open(&std::path::PathBuf::from(send_log), SEND_SEQUENCE_MEMORY)
            }
            None => {
                let mut p = cache_dir()?;
                std::fs::create_dir_all(&p)?;
                p.push("send-log.sqlite3");
                sendlog::SendLog::open(&p, SEND_SEQUENCE_MEMORY)
            }
        },
    }
}

fn matches_to_id_and_query(
    matches: &Matches,
) -> Result<(Option<i64>, tquery::Query), failure::Error> {
    let query: tquery::Query = if !matches.free.is_empty() {
        match tquery::parse(&matches.free.join("•")) {
            Ok(query) => query,
            Err(e) => {
                tquery::report_parse_error(e);
                failure::bail!("query parse error");
            }
        }
    } else {
        failure::bail!("you must specify a query");
    };
    let id = tquery::get_id_query(&query);
    Ok((id, query))
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
        if !repo_path.is_empty() {
            args.push(repo_path);
        }
        args
    } else {
        vec!["archivist".to_owned(), "serve".to_owned(), repo]
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

enum ListFormat {
    Human,
    Jsonl,
}

fn list_main(args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();
    opts.optopt(
        "r",
        "repository",
        "URI of repository to list items from.",
        "REPO",
    );
    opts.optopt(
        "k",
        "key",
        "master key to decrypt items during listing/search.",
        "PATH",
    );
    opts.optopt(
        "",
        "format",
        "Output format, valid values are human | jsonl",
        "PATH",
    );
    query_cache_opt(&mut opts);

    let matches = default_parse_opts(opts, &args[..]);

    let list_format = match matches.opt_str("format") {
        Some(f) => match &f[..] {
            "jsonl" => ListFormat::Jsonl,
            "human" => ListFormat::Human,
            _ => failure::bail!("invalid --format, expected one of human | jsonl"),
        },
        None => ListFormat::Human,
    };

    let key = if matches.opt_present("key") {
        matches.opt_str("key").unwrap()
    } else if let Some(s) = std::env::var_os("ARCHIVIST_MASTER_KEY") {
        s.into_string().unwrap()
    } else {
        failure::bail!("please set --key or the env var ARCHIVIST_MASTER_KEY");
    };

    let key = keys::Key::load_from_file(&key)?;
    let master_key_id = key.master_key_id();
    let mut metadata_dctx = match key {
        keys::Key::MasterKeyV1(k) => crypto::DecryptionContext::new(k.metadata_sk),
        keys::Key::MetadataKeyV1(k) => crypto::DecryptionContext::new(k.metadata_sk),
        _ => failure::bail!("provided key is a not a master decryption key"),
    };
    let mut query: Option<tquery::Query> = None;

    if !matches.free.is_empty() {
        query = match tquery::parse(&matches.free.join("•")) {
            Err(e) => {
                tquery::report_parse_error(e);
                std::process::exit(1);
            }
            Ok(query) => Some(query),
        };
    }

    let mut query_cache = matches_to_query_cache(&matches)?;

    let warned_wrong_key = &mut false;
    let mut f = |id: i64, metadata: itemset::VersionedItemMetadata| match metadata {
        itemset::VersionedItemMetadata::V1(metadata) => {
            if metadata.plain_text_metadata.master_key_id != master_key_id {
                if !*warned_wrong_key {
                    *warned_wrong_key = true;
                    eprintln!("NOTE: Search skipping items encrypted with different master key.")
                }
                return Ok(());
            }

            let encrypted_metadata = metadata.decrypt_metadata(&mut metadata_dctx)?;
            let mut tags = encrypted_metadata.tags;
            tags.insert("id".to_string(), Some(id.to_string()));

            let doprint = match query {
                Some(ref query) => tquery::query_matches(query, &tags),
                None => true,
            };

            let mut tags: Vec<(String, Option<String>)> = tags.into_iter().collect();
            tags.sort_by(|(k1, _), (k2, _)| match (k1.as_str(), k2.as_str()) {
                ("id", _) => std::cmp::Ordering::Less,
                (_, "id") => std::cmp::Ordering::Greater,
                _ => k1.partial_cmp(k2).unwrap(),
            });

            if doprint {
                match list_format {
                    ListFormat::Human => {
                        for (i, (k, v)) in tags.iter().enumerate() {
                            if i != 0 {
                                print!(" ");
                            }
                            print!("{}", k);
                            match v {
                                Some(v) => {
                                    print!("=\"{}\"", v.replace("\\", "\\\\").replace("\"", "\\\""))
                                }
                                None => (),
                            }
                        }
                        println!();
                    }
                    ListFormat::Jsonl => {
                        print!("{{");
                        for (i, (k, v)) in tags.iter().enumerate() {
                            if i != 0 {
                                print!(", ");
                            }
                            match v {
                                Some(v) => print!(
                                    "{}:{}",
                                    serde_json::to_string(&k)?,
                                    serde_json::to_string(&v)?
                                ),
                                None => print!("{} : true", serde_json::to_string(&k)?),
                            }
                        }
                        println!("}}");
                    }
                }
            }

            Ok(())
        }
    };

    let mut serve_proc = matches_to_serve_process(&matches)?;
    let mut serve_out = serve_proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.stdin.as_mut().unwrap();

    client::handle_server_info(&mut serve_out)?;
    client::sync(&mut query_cache, &mut serve_out, &mut serve_in)?;
    client::hangup(&mut serve_in)?;

    let mut tx = query_cache.transaction()?;
    tx.walk_items(&mut f)?;

    Ok(())
}

fn send_main(mut args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();

    opts.optopt("k", "key", "Encryption key.", "PATH");
    opts.optopt(
        "r",
        "repository",
        "URI of repository to save data info.",
        "REPO",
    );
    opts.optflag(
        "",
        "no-compression",
        "Disable compression (Use for for already compressed/encrypted data).",
    );
    opts.optflag(
        "e",
        "exec",
        "Treat all arguments after '::' as a command to run, ensuring it succeeds before committing the send.",
    );
    opts.optflag(
        "",
        "no-stat-cache",
        "Do not use the stat caching when sending a directory snapshot.",
    );
    opts.optopt(
        "",
        "send-log",
        "Use send log to avoid resending data that was sent previously.",
        "PATH",
    );

    let (args, source_args) = {
        let mut idx = None;
        for (i, v) in args.iter().enumerate() {
            if v == "::" {
                idx = Some(i);
                break;
            }
        }
        match idx {
            Some(i) => {
                args.remove(i);
                let source_args = args.split_off(i);
                (args, source_args)
            }
            None => (args, Vec::new()),
        }
    };

    let matches = default_parse_opts(opts, &args);

    let key = if matches.opt_present("key") {
        matches.opt_str("key").unwrap()
    } else if let Some(s) = std::env::var_os("ARCHIVIST_SEND_KEY") {
        s.into_string().unwrap()
    } else {
        failure::bail!("please set --key or the env var ARCHIVIST_SEND_KEY");
    };

    let key = keys::Key::load_from_file(&key)?;
    let master_key_id = key.master_key_id();
    let (hash_key, data_ectx, metadata_ectx) = match key {
        keys::Key::MasterKeyV1(k) => {
            let hash_key = crypto::derive_hash_key(&k.hash_key_part_1, &k.hash_key_part_2);
            let data_ectx = crypto::EncryptionContext::new(&k.data_pk);
            let metadata_ectx = crypto::EncryptionContext::new(&k.metadata_pk);
            (hash_key, data_ectx, metadata_ectx)
        }
        keys::Key::SendKeyV1(k) => {
            let hash_key = crypto::derive_hash_key(&k.hash_key_part_1, &k.hash_key_part_2);
            let data_ectx = crypto::EncryptionContext::new(&k.data_pk);
            let metadata_ectx = crypto::EncryptionContext::new(&k.metadata_pk);
            (hash_key, data_ectx, metadata_ectx)
        }
        _ => failure::bail!("can only send data with a master key or send key."),
    };

    let data_source = if matches.opt_present("exec") {
        client::DataSource::Subprocess(source_args)
    } else if source_args.is_empty() {
        client::DataSource::Readable(Box::new(Box::new(std::io::stdin())))
    } else {
        if !source_args.len() == 1 {
            failure::bail!("expected a single data source, got {:?}", source_args);
        }
        let input_path = &source_args[0];
        let md = match std::fs::metadata(input_path) {
            Ok(md) => md,
            Err(err) => failure::bail!("unable to open input source {:?}: {}", input_path, err),
        };
        if md.is_dir() {
            client::DataSource::Directory(std::convert::From::from(input_path))
        } else if md.is_file() {
            client::DataSource::Readable(Box::new(std::fs::File::open(input_path)?))
        } else {
            failure::bail!("{} is not a file or a directory", source_args[0]);
        }
    };

    let mut tags = BTreeMap::<String, Option<String>>::new();

    let tag_re = regex::Regex::new(r"^([^=]+)(?:=(.+))?$")?;
    let mut tag_size: usize = 0;
    for a in &matches.free {
        match tag_re.captures(&a) {
            Some(caps) => {
                let t = &caps[1];
                let v = caps.get(2);
                match v {
                    Some(v) => {
                        tag_size += t.len() + v.as_str().len();
                        tags.insert(t.to_string(), Some(v.as_str().to_string()))
                    }
                    None => {
                        tag_size += t.len();
                        tags.insert(t.to_string(), None)
                    }
                };
            }
            None => failure::bail!("argument '{}' is not a valid tag value.", a),
        }

        if tag_size > itemset::MAX_TAG_SET_SIZE {
            failure::bail!("tags must not exceed {} bytes", itemset::MAX_TAG_SET_SIZE);
        }
    }

    let send_log = matches_to_send_log(&matches)?;
    let mut serve_proc = matches_to_serve_process(&matches)?;
    let mut serve_out = serve_proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.stdin.as_mut().unwrap();
    let mut ctx = client::SendContext {
        use_stat_cache: !matches.opt_present("no-stat-cache"),
        compression: if matches.opt_present("no-compression") {
            crypto::DataCompression::None
        } else {
            crypto::DataCompression::Zstd
        },
        master_key_id,
        hash_key,
        data_ectx,
        metadata_ectx,
    };

    client::handle_server_info(&mut serve_out)?;
    let id = client::send(
        &mut ctx,
        &mut serve_out,
        &mut serve_in,
        send_log,
        tags,
        data_source,
    )?;
    client::hangup(&mut serve_in)?;

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
    query_cache_opt(&mut opts);

    let matches = default_parse_opts(opts, &args[..]);

    let key = if matches.opt_present("key") {
        matches.opt_str("key").unwrap()
    } else if let Some(s) = std::env::var_os("ARCHIVIST_MASTER_KEY") {
        s.into_string().unwrap()
    } else {
        failure::bail!("please set --key or the env var ARCHIVIST_MASTER_KEY");
    };
    let key = keys::Key::load_from_file(&key)?;
    let master_key_id = key.master_key_id();
    let (hash_key_part_1, data_dctx, mut metadata_dctx) = match key {
        keys::Key::MasterKeyV1(k) => {
            let hash_key_part_1 = k.hash_key_part_1.clone();
            let data_dctx = crypto::DecryptionContext::new(k.data_sk);
            let metadata_dctx = crypto::DecryptionContext::new(k.metadata_sk);
            (hash_key_part_1, data_dctx, metadata_dctx)
        }
        _ => failure::bail!("provided key is a not a master decryption key"),
    };

    let (id, query) = matches_to_id_and_query(&matches)?;
    let mut serve_proc = matches_to_serve_process(&matches)?;
    let mut serve_out = serve_proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.stdin.as_mut().unwrap();

    client::handle_server_info(&mut serve_out)?;

    let id = match (id, query) {
        (Some(id), _) => id,
        (_, query) => {
            let mut query_cache = matches_to_query_cache(&matches)?;

            client::sync(&mut query_cache, &mut serve_out, &mut serve_in)?;

            let mut n_matches: u64 = 0;
            let mut id = -1;

            let mut f = |qid: i64, metadata: itemset::VersionedItemMetadata| match metadata {
                itemset::VersionedItemMetadata::V1(metadata) => {
                    if master_key_id != metadata.plain_text_metadata.master_key_id {
                        return Ok(());
                    }

                    let encrypted_metadata = metadata.decrypt_metadata(&mut metadata_dctx)?;
                    let mut tags = encrypted_metadata.tags;
                    tags.insert("id".to_string(), Some(qid.to_string()));
                    if tquery::query_matches(&query, &tags) {
                        n_matches += 1;
                        id = qid;
                    }
                    Ok(())
                }
            };

            let mut tx = query_cache.transaction()?;
            tx.walk_items(&mut f)?;

            if n_matches != 1 {
                failure::bail!(
                    "the provided query matched {} items, need a single match",
                    n_matches
                );
            }
            id
        }
    };

    client::request_data_stream(
        client::RequestContext {
            master_key_id,
            hash_key_part_1,
            data_dctx,
            metadata_dctx,
        },
        id,
        &mut serve_out,
        &mut serve_in,
        &mut std::io::stdout(),
    )?;
    client::hangup(&mut serve_in)?;

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
    query_cache_opt(&mut opts);
    opts.optopt("k", "key", "decryption key for querying.", "PATH");
    opts.optflag("", "allow-many", "Allow multiple removals.");

    let matches = default_parse_opts(opts, &args[..]);

    let (id, query) = matches_to_id_and_query(&matches)?;

    let mut serve_proc = matches_to_serve_process(&matches)?;
    let mut serve_out = serve_proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.stdin.as_mut().unwrap();

    client::handle_server_info(&mut serve_out)?;

    let ids: Vec<i64> = match (id, query) {
        (Some(id), _) => vec![id],
        (_, query) => {
            let mut query_cache = matches_to_query_cache(&matches)?;

            client::sync(&mut query_cache, &mut serve_out, &mut serve_in)?;

            let key = if matches.opt_present("key") {
                matches.opt_str("key").unwrap()
            } else if let Some(s) = std::env::var_os("ARCHIVIST_MASTER_KEY") {
                s.into_string().unwrap()
            } else {
                failure::bail!("please set --key or the env var ARCHIVIST_MASTER_KEY");
            };

            let key = keys::Key::load_from_file(&key)?;
            let master_key_id = key.master_key_id();
            let mut metadata_dctx = match key {
                keys::Key::MasterKeyV1(k) => crypto::DecryptionContext::new(k.metadata_sk),
                keys::Key::MetadataKeyV1(k) => crypto::DecryptionContext::new(k.metadata_sk),
                _ => failure::bail!("provided key is a not a master decryption key"),
            };
            let mut ids = Vec::new();

            let mut f = |id: i64, metadata: itemset::VersionedItemMetadata| match metadata {
                itemset::VersionedItemMetadata::V1(metadata) => {
                    if metadata.plain_text_metadata.master_key_id != master_key_id {
                        return Ok(());
                    }
                    let encrypted_metadata = metadata.decrypt_metadata(&mut metadata_dctx)?;
                    let mut tags = encrypted_metadata.tags;

                    tags.insert("id".to_string(), Some(id.to_string()));
                    if tquery::query_matches(&query, &tags) {
                        ids.push(id);
                    }
                    Ok(())
                }
            };
            let mut tx = query_cache.transaction()?;
            tx.walk_items(&mut f)?;

            if ids.len() != 1 && !matches.opt_present("allow-many") {
                failure::bail!(
                    "the provided query matched {} items, need a single match unless --allow-many is specified",
                    ids.len()
                );
            };

            ids
        }
    };

    for ids in ids.chunks(128) {
        client::remove(ids.to_vec(), &mut serve_out, &mut serve_in)?;
    }

    client::hangup(&mut serve_in)?;

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
    client::handle_server_info(&mut serve_out)?;
    let stats = client::gc(&mut serve_out, &mut serve_in)?;
    client::hangup(&mut serve_in)?;
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
    crypto::init();

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
        "new-metadata-key" => new_metadata_key_main(args),
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
