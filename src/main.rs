pub mod address;
pub mod chunk_storage;
pub mod chunker;
pub mod client;
pub mod crypto;
pub mod dir_chunk_storage;
pub mod external_chunk_storage;
pub mod fsutil;
pub mod hex;
pub mod htree;
pub mod itemset;
pub mod keys;
pub mod protocol;
pub mod querycache;
pub mod repository;
pub mod rollsum;
pub mod sendlog;
pub mod server;
pub mod sqlite3_chunk_storage;
pub mod tquery;
pub mod xid;
pub mod xtar;

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
    cache_dir.push("bupstash");
    Ok(cache_dir)
}

fn print_help_and_exit(subcommand: &str, opts: &Options) {
    let brief = match subcommand {
        "init" => include_str!("../doc/cli/init.txt"),
        "help" => include_str!("../doc/cli/help.txt"),
        "new-key" => include_str!("../doc/cli/new-key.txt"),
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

fn query_opts(opts: &mut Options) {
    opts.optopt(
        "",
        "query-cache",
        "Path to the query cache (used for storing synced items before search).",
        "PATH",
    );
    opts.optflag(
        "",
        "utc-timestamps",
        "Do not convert the 'timestamp' tag to local time (as is done by default).",
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
        None => repository::StorageEngineSpec::Dir {
            dir_path: "./data".to_string(),
        },
    };

    repository::Repo::init(std::path::Path::new(&matches.free[0]), backend)
}

fn matches_to_key(matches: &Matches) -> Result<keys::Key, failure::Error> {
    match matches.opt_str("key") {
        Some(k) => Ok(keys::Key::load_from_file(&k)?),
        None => {
            if let Some(k) = std::env::var_os("BUPSTASH_KEY") {
                Ok(keys::Key::load_from_file(&k.into_string().unwrap())?)
            } else if let Some(cmd) = std::env::var_os("BUPSTASH_KEY_COMMAND") {
                match shlex::split(&cmd.into_string().unwrap()) {
                    Some(mut args) => {
                        if args.is_empty() {
                            failure::bail!("BUPSTASH_KEY_COMMAND must not be empty")
                        }
                        let bin = args.remove(0);

                        match std::process::Command::new(bin).args(args).output() {
                            Ok(key_data) => Ok(keys::Key::from_slice(&key_data.stdout)?),
                            Err(e) => failure::bail!("error running BUPSTASH_KEY_COMMAND: {}", e),
                        }
                    }
                    None => failure::bail!("unable to parse BUPSTASH_KEY_COMMAND"),
                }
            } else {
                failure::bail!("please set --key, BUPSTASH_KEY or BUPSTASH_KEY_COMMAND");
            }
        }
    }
}

fn new_key_main(args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();
    opts.reqopt("o", "output", "set output file.", "PATH");
    let matches = default_parse_opts(opts, &args[..]);
    let primary_key = keys::Key::PrimaryKeyV1(keys::PrimaryKey::gen());
    primary_key.write_to_file(&matches.opt_str("o").unwrap())
}

fn new_send_key_main(args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();
    opts.reqopt("k", "key", "primary key to derive put-key from.", "PATH");
    opts.reqopt("o", "output", "output file.", "PATH");
    let matches = default_parse_opts(opts, &args[..]);
    let k = matches_to_key(&matches)?;
    match k {
        keys::Key::PrimaryKeyV1(primary_key) => {
            let send_key = keys::Key::SendKeyV1(keys::SendKey::gen(&primary_key));
            send_key.write_to_file(&matches.opt_str("o").unwrap())
        }
        _ => failure::bail!("key is not a primary key"),
    }
}

fn new_metadata_key_main(args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();
    opts.reqopt(
        "k",
        "key",
        "primary key to derive metadata key from.",
        "PATH",
    );
    opts.reqopt("o", "output", "output file.", "PATH");
    let matches = default_parse_opts(opts, &args[..]);
    let k = matches_to_key(&matches)?;
    match k {
        keys::Key::PrimaryKeyV1(primary_key) => {
            let send_key = keys::Key::MetadataKeyV1(keys::MetadataKey::gen(&primary_key));
            send_key.write_to_file(&matches.opt_str("o").unwrap())
        }
        _ => failure::bail!("key is not a primary key"),
    }
}

fn matches_to_query_cache(matches: &Matches) -> Result<querycache::QueryCache, failure::Error> {
    match matches.opt_str("query-cache") {
        Some(query_cache) => querycache::QueryCache::open(&std::path::PathBuf::from(query_cache)),
        None => match std::env::var_os("BUPSTASH_QUERY_CACHE") {
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

fn matches_to_id_and_query(
    matches: &Matches,
) -> Result<(Option<xid::Xid>, tquery::Query), failure::Error> {
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
    let mut serve_cmd_args = {
        let repo = if matches.opt_present("repository") {
            Some(matches.opt_str("repository").unwrap())
        } else if let Some(r) = std::env::var_os("BUPSTASH_REPOSITORY") {
            Some(r.into_string().unwrap())
        } else {
            None
        };

        match repo {
            Some(repo) => {
                if repo.starts_with("ssh://") {
                    let re = regex::Regex::new(r"^ssh://(?:([a-zA-Z0-9]+)@)?([^/]*)(.*)$")?;
                    let caps = re.captures(&repo).unwrap();

                    let mut args = vec!["ssh".to_owned()];

                    if let Some(user) = caps.get(1) {
                        args.push("-o".to_owned());
                        args.push("User=".to_owned() + user.as_str());
                    }
                    args.push(caps[2].to_string());
                    args.push("--".to_owned());
                    args.push("bupstash".to_owned());
                    args.push("serve".to_owned());
                    let repo_path = caps[3].to_string();
                    if !repo_path.is_empty() {
                        args.push(repo_path);
                    }
                    args
                } else {
                    vec!["bupstash".to_owned(), "serve".to_owned(), repo]
                }
            }
            None => {
                if let Some(connect_cmd) = std::env::var_os("BUPSTASH_REPOSITORY_COMMAND") {
                    match shlex::split(&connect_cmd.into_string().unwrap()) {
                        Some(args) => {
                            if args.is_empty() {
                                failure::bail!(
                                    "BUPSTASH_REPOSITORY_COMMAND should have at least one element"
                                );
                            }
                            args
                        }
                        None => failure::bail!("unable to parse BUPSTASH_REPOSITORY_COMMAND"),
                    }
                } else {
                    failure::bail!(
                        "please set --repository, BUPSTASH_REPOSITORY or BUPSTASH_REPOSITORY_COMMAND"
                    );
                }
            }
        }
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
        "primary or metadata key to decrypt item metadata with during listing.",
        "PATH",
    );
    opts.optopt(
        "",
        "format",
        "Output format, valid values are human | jsonl",
        "PATH",
    );
    query_opts(&mut opts);

    let matches = default_parse_opts(opts, &args[..]);

    let list_format = match matches.opt_str("format") {
        Some(f) => match &f[..] {
            "jsonl" => ListFormat::Jsonl,
            "human" => ListFormat::Human,
            _ => failure::bail!("invalid --format, expected one of human | jsonl"),
        },
        None => ListFormat::Human,
    };

    let key = matches_to_key(&matches)?;
    let primary_key_id = key.primary_key_id();
    let mut metadata_dctx = match key {
        keys::Key::PrimaryKeyV1(k) => crypto::DecryptionContext::new(k.metadata_sk),
        keys::Key::MetadataKeyV1(k) => crypto::DecryptionContext::new(k.metadata_sk),
        _ => failure::bail!("provided key is not a primary key"),
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
    let mut f =
        |_op_id: i64, item_id: xid::Xid, metadata: itemset::VersionedItemMetadata| match metadata {
            itemset::VersionedItemMetadata::V1(metadata) => {
                if metadata.plain_text_metadata.primary_key_id != primary_key_id {
                    if !*warned_wrong_key {
                        *warned_wrong_key = true;
                        eprintln!(
                            "NOTE: Search skipping items encrypted with different primary key."
                        )
                    }
                    return Ok(());
                }

                let encrypted_metadata = metadata.decrypt_metadata(&mut metadata_dctx)?;
                let mut tags = encrypted_metadata.tags;

                // Add special builtin tags.
                tags.insert("id".to_string(), Some(item_id.to_string()));

                let ts = if matches.opt_present("utc-timestamps") {
                    encrypted_metadata.timestamp.format("%F %T").to_string()
                } else {
                    let local_ts: chrono::DateTime<chrono::Local> =
                        chrono::DateTime::from(encrypted_metadata.timestamp);
                    local_ts.format("%F %T").to_string()
                };
                tags.insert("timestamp".to_string(), Some(ts));

                let doprint = match query {
                    Some(ref query) => tquery::query_matches(query, &tags),
                    None => true,
                };

                let mut tags: Vec<(String, Option<String>)> = tags.into_iter().collect();

                // Custom sort to be more human friendly.
                tags.sort_by(|(k1, _), (k2, _)| match (k1.as_str(), k2.as_str()) {
                    ("id", _) => std::cmp::Ordering::Less,
                    (_, "id") => std::cmp::Ordering::Greater,
                    ("name", _) => std::cmp::Ordering::Less,
                    (_, "name") => std::cmp::Ordering::Greater,
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
                                    Some(v) => print!(
                                        "=\"{}\"",
                                        v.replace("\\", "\\\\").replace("\"", "\\\"")
                                    ),
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

fn put_main(mut args: Vec<String>) -> Result<(), failure::Error> {
    let mut opts = default_cli_opts();

    opts.optopt(
        "k",
        "key",
        "Primary or put key to encrypt data with.",
        "PATH",
    );
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
        "",
        "no-default-tags",
        "Disable the default tags 'name', 'timestamp'",
    );
    opts.optflag(
        "e",
        "exec",
        "Treat all arguments after '::' as a command to run, ensuring it succeeds before committing the send.",
    );
    opts.optflag(
        "",
        "no-stat-cache",
        "Do not use stat caching to skip sending directories to the server.",
    );
    opts.optflag(
        "",
        "no-send-log",
        "Disable logging of previously sent data, implies --no-stat-cache.",
    );

    opts.optopt(
        "",
        "send-log",
        "Use the file at PATH as a 'send log', used to skip data that was previously to the server.",
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

    let compression = if matches.opt_present("no-compression") {
        crypto::DataCompression::None
    } else {
        crypto::DataCompression::Zstd
    };

    let use_stat_cache = !matches.opt_present("no-stat-cache");

    let send_log = if matches.opt_present("no-send-log") {
        None
    } else {
        match matches.opt_str("send-log") {
            Some(send_log) => Some(sendlog::SendLog::open(&std::path::PathBuf::from(send_log))?),
            None => match std::env::var_os("BUPSTASH_SEND_LOG") {
                Some(send_log) => {
                    Some(sendlog::SendLog::open(&std::path::PathBuf::from(send_log))?)
                }
                None => {
                    let mut p = cache_dir()?;
                    std::fs::create_dir_all(&p)?;
                    p.push("send-log.sqlite3");
                    Some(sendlog::SendLog::open(&p)?)
                }
            },
        }
    };

    let key = matches_to_key(&matches)?;
    let primary_key_id = key.primary_key_id();
    let send_key_id = key.id();
    let (hash_key, data_ectx, metadata_ectx) = match key {
        keys::Key::PrimaryKeyV1(k) => {
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
        _ => failure::bail!("can only send data with a primary-key or put-key."),
    };

    let mut tags = BTreeMap::<String, Option<String>>::new();

    let default_tags = !matches.opt_present("no-default-tags");

    let data_source: client::DataSource;

    if matches.opt_present("exec") {
        data_source = client::DataSource::Subprocess(source_args)
    } else if source_args.is_empty() {
        data_source = client::DataSource::Readable(Box::new(Box::new(std::io::stdin())))
    } else {
        if !source_args.len() == 1 {
            failure::bail!("expected a single data source, got {:?}", source_args);
        }
        let input_path: std::path::PathBuf = std::convert::From::from(&source_args[0]);

        let md = match std::fs::metadata(&input_path) {
            Ok(md) => md,
            Err(err) => failure::bail!("unable to open input source {:?}: {}", input_path, err),
        };

        let name = match input_path.file_name() {
            Some(name) => name.to_string_lossy().to_string(),
            None => "rootfs".to_string(),
        };

        if md.is_dir() {
            if default_tags {
                tags.insert("name".to_string(), Some(name + ".tar"));
            }

            data_source = client::DataSource::Directory(input_path)
        } else if md.is_file() {
            if default_tags {
                tags.insert("name".to_string(), Some(name));
            }

            data_source = client::DataSource::Readable(Box::new(std::fs::File::open(input_path)?))
        } else {
            failure::bail!("{} is not a file or a directory", source_args[0]);
        }
    };

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

    // No easy way to compute the tag set length without actually encoding it due
    // to var ints in the bare encoding.
    if serde_bare::to_vec(&tags)?.len() > itemset::MAX_TAG_SET_SIZE {
        failure::bail!("tags must not exceed {} bytes", itemset::MAX_TAG_SET_SIZE);
    }

    let mut serve_proc = matches_to_serve_process(&matches)?;
    let mut serve_out = serve_proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.stdin.as_mut().unwrap();
    let mut ctx = client::SendContext {
        compression,
        use_stat_cache,
        primary_key_id,
        send_key_id,
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

    opts.optopt("k", "key", "Primary key to decrypt data with.", "PATH");
    opts.optopt(
        "r",
        "repository",
        "URI of repository to fetch data from.",
        "REPO",
    );
    query_opts(&mut opts);

    let matches = default_parse_opts(opts, &args[..]);

    let key = matches_to_key(&matches)?;
    let primary_key_id = key.primary_key_id();
    let (hash_key_part_1, data_dctx, mut metadata_dctx) = match key {
        keys::Key::PrimaryKeyV1(k) => {
            let hash_key_part_1 = k.hash_key_part_1.clone();
            let data_dctx = crypto::DecryptionContext::new(k.data_sk);
            let metadata_dctx = crypto::DecryptionContext::new(k.metadata_sk);
            (hash_key_part_1, data_dctx, metadata_dctx)
        }
        _ => failure::bail!("provided key is not a decryption key"),
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
            let mut id = xid::Xid::default();

            let mut f = |_op_id: i64,
                         item_id: xid::Xid,
                         metadata: itemset::VersionedItemMetadata| {
                match metadata {
                    itemset::VersionedItemMetadata::V1(metadata) => {
                        if primary_key_id != metadata.plain_text_metadata.primary_key_id {
                            return Ok(());
                        }

                        let encrypted_metadata = metadata.decrypt_metadata(&mut metadata_dctx)?;
                        let mut tags = encrypted_metadata.tags;

                        // Add special builtin tags.
                        tags.insert("id".to_string(), Some(item_id.to_string()));

                        let ts = if matches.opt_present("utc-timestamps") {
                            encrypted_metadata.timestamp.format("%F %T").to_string()
                        } else {
                            let local_ts: chrono::DateTime<chrono::Local> =
                                chrono::DateTime::from(encrypted_metadata.timestamp);
                            local_ts.format("%F %T").to_string()
                        };
                        tags.insert("timestamp".to_string(), Some(ts));

                        if tquery::query_matches(&query, &tags) {
                            n_matches += 1;
                            id = item_id;
                        }
                        Ok(())
                    }
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
            primary_key_id,
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
    query_opts(&mut opts);
    opts.optopt(
        "k",
        "key",
        "Primary or metadata key to decrypt metadata with.",
        "PATH",
    );
    opts.optflag("", "allow-many", "Allow multiple removals.");

    let matches = default_parse_opts(opts, &args[..]);

    let (id, query) = matches_to_id_and_query(&matches)?;

    let mut serve_proc = matches_to_serve_process(&matches)?;
    let mut serve_out = serve_proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.stdin.as_mut().unwrap();

    client::handle_server_info(&mut serve_out)?;

    let ids: Vec<xid::Xid> = match (id, query) {
        (Some(id), _) => vec![id],
        (_, query) => {
            let mut query_cache = matches_to_query_cache(&matches)?;

            client::sync(&mut query_cache, &mut serve_out, &mut serve_in)?;

            let key = matches_to_key(&matches)?;
            let primary_key_id = key.primary_key_id();
            let mut metadata_dctx = match key {
                keys::Key::PrimaryKeyV1(k) => crypto::DecryptionContext::new(k.metadata_sk),
                keys::Key::MetadataKeyV1(k) => crypto::DecryptionContext::new(k.metadata_sk),
                _ => failure::bail!("provided key is not a decryption key"),
            };
            let mut ids = Vec::new();

            let mut f = |_op_id: i64,
                         item_id: xid::Xid,
                         metadata: itemset::VersionedItemMetadata| {
                match metadata {
                    itemset::VersionedItemMetadata::V1(metadata) => {
                        if metadata.plain_text_metadata.primary_key_id != primary_key_id {
                            return Ok(());
                        }
                        let encrypted_metadata = metadata.decrypt_metadata(&mut metadata_dctx)?;
                        let mut tags = encrypted_metadata.tags;

                        // Add special builtin tags.
                        tags.insert("id".to_string(), Some(item_id.to_string()));

                        let ts = if matches.opt_present("utc-timestamps") {
                            encrypted_metadata.timestamp.format("%F %T").to_string()
                        } else {
                            let local_ts: chrono::DateTime<chrono::Local> =
                                chrono::DateTime::from(encrypted_metadata.timestamp);
                            local_ts.format("%F %T").to_string()
                        };
                        tags.insert("timestamp".to_string(), Some(ts));

                        if tquery::query_matches(&query, &tags) {
                            ids.push(item_id);
                        }
                        Ok(())
                    }
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

    client::remove(ids, &mut serve_out, &mut serve_in)?;
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
        "allow-put",
        "allow client to put more entries into the repository.",
    );
    opts.optflag(
        "",
        "allow-remove",
        "allow client to remove repository entries.",
    );
    opts.optflag(
        "",
        "allow-gc",
        "allow client to run the repository garbage collector.",
    );
    opts.optflag(
        "",
        "allow-get",
        "allow client to get data from the repository.",
    );
    opts.optflag("", "allow-list", "allow client to list repository entries.");
    let matches = default_parse_opts(opts, &args[..]);

    if matches.free.len() != 1 {
        die("Expected a single path to initialize.".to_string());
    }

    let mut allow_put = true;
    let mut allow_remove = true;
    let mut allow_gc = true;
    let mut allow_get = true;
    let mut allow_list = true;

    if matches.opt_present("allow-put")
        || matches.opt_present("allow-remove")
        || matches.opt_present("allow-gc")
        || matches.opt_present("allow-get")
        || matches.opt_present("allow-list")
    {
        allow_put = matches.opt_present("allow-put");
        allow_remove = matches.opt_present("allow-remove");
        allow_gc = matches.opt_present("allow-gc");
        allow_get = matches.opt_present("allow-get");
        allow_list = matches.opt_present("allow-list");
    }

    server::serve(
        server::ServerConfig {
            allow_put,
            allow_remove,
            allow_gc,
            allow_get,
            allow_list,
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
        "new-key" => new_key_main(args),
        "new-put-key" => new_send_key_main(args),
        "new-metadata-key" => new_metadata_key_main(args),
        "list" => list_main(args),
        "put" => put_main(args),
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
        die(format!("bupstash {}: {}", subcommand, err));
    }
}
