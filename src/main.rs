pub mod abloom;
pub mod acache;
pub mod address;
pub mod base64;
pub mod chunk_storage;
pub mod chunker;
pub mod client;
pub mod compression;
pub mod crypto;
pub mod dir_chunk_storage;
pub mod external_chunk_storage;
pub mod fmtutil;
pub mod fstx;
pub mod fsutil;
pub mod hex;
pub mod htree;
pub mod index;
pub mod keys;
pub mod migrate;
pub mod oplog;
pub mod pem;
pub mod protocol;
pub mod query;
pub mod querycache;
pub mod repository;
pub mod rollsum;
pub mod sendlog;
pub mod server;
pub mod sodium;
pub mod xid;
pub mod xtar;

use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};

fn die(s: String) -> ! {
    let _ = writeln!(std::io::stderr(), "{}", s);
    std::process::exit(1);
}

fn cache_dir() -> Result<std::path::PathBuf, anyhow::Error> {
    let mut cache_dir = match std::env::var_os("XDG_CACHE_HOME") {
        Some(cache_dir) => std::path::PathBuf::from(&cache_dir),
        None => match std::env::var_os("HOME") {
            Some(home) => {
                let mut h = std::path::PathBuf::from(&home);
                h.push(".cache");
                h
            }
            None => anyhow::bail!("unable to determine cache dir from XDG_CACHE_HOME or HOME"),
        },
    };
    cache_dir.push("bupstash");
    Ok(cache_dir)
}

fn print_help_and_exit(subcommand: &str, opts: &getopts::Options) {
    let brief = match subcommand {
        "init" => include_str!("../doc/cli/init.txt"),
        "help" => include_str!("../doc/cli/help.txt"),
        "new-key" => include_str!("../doc/cli/new-key.txt"),
        "new-sub-key" => include_str!("../doc/cli/new-sub-key.txt"),
        "put" => include_str!("../doc/cli/put.txt"),
        "list" => include_str!("../doc/cli/list.txt"),
        "list-contents" => include_str!("../doc/cli/list-contents.txt"),
        "diff" => include_str!("../doc/cli/diff.txt"),
        "get" => include_str!("../doc/cli/get.txt"),
        "rm" | "remove" => include_str!("../doc/cli/rm.txt"),
        "restore-removed" => include_str!("../doc/cli/restore-removed.txt"),
        "gc" => include_str!("../doc/cli/gc.txt"),
        "serve" => include_str!("../doc/cli/serve.txt"),
        "version" => include_str!("../doc/cli/version.txt"),
        "put-benchmark" => "put-benchmark tool.",
        _ => panic!(),
    };
    let _ = std::io::stdout().write_all(opts.usage(brief).as_bytes());
    std::process::exit(0);
}

fn default_cli_opts() -> getopts::Options {
    let mut opts = getopts::Options::new();
    opts.parsing_style(getopts::ParsingStyle::StopAtFirstFree);
    opts.optflag("h", "help", "print this help menu.");
    opts
}

fn query_cli_opts(opts: &mut getopts::Options) {
    opts.optopt(
        "",
        "query-cache",
        "Path to the query cache (used for storing synced items before search). \
        See manual for default values and relevant environment variables.",
        "PATH",
    );
    opts.optflag(
        "",
        "query-encrypted",
        "The query will not decrypt any metadata, allowing you to \
        list items you do not have a decryption key for.\
        This option inserts the pseudo query tag 'decryption-key-id'.",
    );
    opts.optflag(
        "",
        "utc-timestamps",
        "Display and search against timestamps in utc time instead of local time.",
    );
    opts.optflag("q", "quiet", "Suppress progress indicators.");
}

fn repo_cli_opts(opts: &mut getopts::Options) {
    opts.optopt(
        "r",
        "repository",
        "Repository to interact with, if prefixed with ssh:// implies ssh access. \
         Defaults to BUPSTASH_REPOSITORY if not set. \
         See the manual for additional ways to connect to the repository.",
        "REPO",
    );
}

fn parse_cli_opts(opts: getopts::Options, args: &[String]) -> getopts::Matches {
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

fn cli_to_key(matches: &getopts::Matches) -> Result<keys::Key, anyhow::Error> {
    if let Some(k) = cli_to_opt_key(matches)? {
        Ok(k)
    } else {
        anyhow::bail!("please set --key, BUPSTASH_KEY or BUPSTASH_KEY_COMMAND");
    }
}

fn cli_to_opt_key(matches: &getopts::Matches) -> Result<Option<keys::Key>, anyhow::Error> {
    match matches.opt_str("key") {
        Some(k) => Ok(Some(keys::Key::load_from_file(&k)?)),
        None => {
            if let Some(k) = std::env::var_os("BUPSTASH_KEY") {
                Ok(Some(keys::Key::load_from_file(&k.into_string().unwrap())?))
            } else if let Some(cmd) = std::env::var_os("BUPSTASH_KEY_COMMAND") {
                match shlex::split(&cmd.into_string().unwrap()) {
                    Some(mut args) => {
                        if args.is_empty() {
                            anyhow::bail!("BUPSTASH_KEY_COMMAND must not be empty")
                        }
                        let bin = args.remove(0);

                        match std::process::Command::new(bin)
                            .args(args)
                            .stderr(std::process::Stdio::inherit())
                            .stdin(std::process::Stdio::inherit())
                            .output()
                        {
                            Ok(key_data) => Ok(Some(keys::Key::from_slice(&key_data.stdout)?)),
                            Err(e) => anyhow::bail!("error running BUPSTASH_KEY_COMMAND: {}", e),
                        }
                    }
                    None => anyhow::bail!("unable to parse BUPSTASH_KEY_COMMAND"),
                }
            } else {
                Ok(None)
            }
        }
    }
}

fn new_key_main(args: Vec<String>) -> Result<(), anyhow::Error> {
    let mut opts = default_cli_opts();
    opts.reqopt("o", "output", "set output file.", "PATH");
    let matches = parse_cli_opts(opts, &args[..]);
    let primary_key = keys::Key::PrimaryKeyV1(keys::PrimaryKey::gen());
    primary_key.write_to_file(&matches.opt_str("o").unwrap())
}

fn new_sub_key_main(args: Vec<String>) -> Result<(), anyhow::Error> {
    let mut opts = default_cli_opts();

    opts.optopt(
        "k",
        "key",
        "primary key to derive metadata key from.",
        "PATH",
    );

    opts.reqopt("o", "output", "output file.", "PATH");

    opts.optflag(
        "",
        "put",
        "The key is able to encrypt data for put operations.",
    );
    opts.optflag(
        "",
        "list",
        "The key will be able to decrypt metadata and perform queries.",
    );
    opts.optflag(
        "",
        "list-contents",
        "The key will be able to list item contents with 'list-contents' (implies --list).",
    );

    let matches = parse_cli_opts(opts, &args[..]);

    let allow_put = matches.opt_present("put");
    let allow_list = matches.opt_present("list");
    let allow_list_contents = matches.opt_present("list-contents");

    let k = cli_to_key(&matches)?;
    match k {
        keys::Key::PrimaryKeyV1(primary_key) => {
            let subk = keys::Key::SubKeyV1(keys::SubKey::gen(
                &primary_key,
                allow_put,
                allow_list,
                allow_list_contents,
            ));
            subk.write_to_file(&matches.opt_str("o").unwrap())
        }
        _ => anyhow::bail!("key is not a primary key"),
    }
}

fn cli_to_query_cache(matches: &getopts::Matches) -> Result<querycache::QueryCache, anyhow::Error> {
    match matches.opt_str("query-cache") {
        Some(query_cache) => querycache::QueryCache::open(&std::path::PathBuf::from(query_cache)),
        None => match std::env::var_os("BUPSTASH_QUERY_CACHE") {
            Some(query_cache) => {
                querycache::QueryCache::open(&std::path::PathBuf::from(query_cache))
            }
            None => {
                let mut p = cache_dir()?;
                std::fs::create_dir_all(&p)?;
                p.push("bupstash.qcache");
                querycache::QueryCache::open(&p)
            }
        },
    }
}

fn cli_to_id_and_query(
    matches: &getopts::Matches,
) -> Result<(Option<xid::Xid>, query::Query), anyhow::Error> {
    let query: query::Query = if !matches.free.is_empty() {
        match query::parse(&matches.free.join("•")) {
            Ok(query) => query,
            Err(e) => {
                query::report_parse_error(e);
                anyhow::bail!("query parse error");
            }
        }
    } else {
        anyhow::bail!("you must specify a query");
    };
    let id = query::get_id_query(&query);
    Ok((id, query))
}

// Define a smiple wrapper around the serve process
// the wrapper ensures we handle stderr correctly.
struct ServeProcess {
    stderr_reader: Option<std::thread::JoinHandle<()>>,
    proc: std::process::Child,
}

impl ServeProcess {
    fn wait(mut self) -> Result<(), anyhow::Error> {
        let status = self.proc.wait()?;
        if let Some(handle) = self.stderr_reader.take() {
            handle.join().unwrap();
        }
        if !status.success() {
            if let Some(code) = status.code() {
                anyhow::bail!("bupstash serve failed (exit-code={})", code);
            } else {
                anyhow::bail!("bupstash serve failed");
            }
        }
        Ok(())
    }
}

impl Drop for ServeProcess {
    fn drop(&mut self) {
        unsafe { libc::kill(self.proc.id() as i32, libc::SIGTERM) };
        if let Some(handle) = self.stderr_reader.take() {
            handle.join().unwrap();
        }
    }
}

fn cli_to_serve_process(
    matches: &getopts::Matches,
    progress: &indicatif::ProgressBar,
) -> Result<ServeProcess, anyhow::Error> {
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
                    vec![
                        if cfg!(target_os = "openbsd") {
                            std::env::args().next().unwrap()
                        } else {
                            std::env::current_exe()?.to_string_lossy().to_string()
                        },
                        "serve".to_owned(),
                        repo,
                    ]
                }
            }
            None => {
                if let Some(connect_cmd) = std::env::var_os("BUPSTASH_REPOSITORY_COMMAND") {
                    match shlex::split(&connect_cmd.into_string().unwrap()) {
                        Some(args) => {
                            if args.is_empty() {
                                anyhow::bail!(
                                    "BUPSTASH_REPOSITORY_COMMAND should have at least one element"
                                );
                            }
                            args
                        }
                        None => anyhow::bail!("unable to parse BUPSTASH_REPOSITORY_COMMAND"),
                    }
                } else {
                    anyhow::bail!(
                        "please set --repository, BUPSTASH_REPOSITORY or BUPSTASH_REPOSITORY_COMMAND"
                    );
                }
            }
        }
    };

    let bin = serve_cmd_args.remove(0);

    let mut proc = match std::process::Command::new(bin)
        .args(serve_cmd_args)
        .stderr(if progress.is_hidden() {
            std::process::Stdio::inherit()
        } else {
            std::process::Stdio::piped()
        })
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(err) => anyhow::bail!("error spawning serve command: {}", err),
    };

    let stderr_reader = if progress.is_hidden() {
        None
    } else {
        let progress = progress.clone();
        let proc_stderr = proc.stderr.take().unwrap();

        let stderr_reader = std::thread::spawn(move || {
            let buf_reader = std::io::BufReader::new(proc_stderr);
            for line in buf_reader.lines() {
                if let Ok(line) = line {
                    progress.println(&line);
                    // Theres a tiny race condition here where we may print an
                    // error line twice, I can't see how to fix this unless we
                    // rewrite the progress bar library to report if the print happened.
                    if progress.is_finished() || progress.is_hidden() {
                        let _ = writeln!(std::io::stderr(), "{}", line);
                    }
                }
            }
        });

        Some(stderr_reader)
    };

    Ok(ServeProcess {
        stderr_reader,
        proc,
    })
}

fn cli_to_opened_serve_process(
    matches: &getopts::Matches,
    progress: &indicatif::ProgressBar,
    open_mode: protocol::OpenMode,
) -> Result<ServeProcess, anyhow::Error> {
    let mut retry_duration = 2;
    let mut retry_count: u64 = 0;

    loop {
        let mut remote = cli_to_serve_process(matches, progress)?;
        // Temporary borrow of the stdin/stdout so we can handle
        // server retry back pressure if the server implements this.
        let mut proc_stdin = remote.proc.stdin.take().unwrap();
        let mut proc_stdout = remote.proc.stdout.take().unwrap();

        match open_mode {
            protocol::OpenMode::ReadWrite | protocol::OpenMode::Gc => {
                progress.set_message(&"acquiring repository lock...");
            }
            _ => (),
        }

        match client::open_repository(&mut proc_stdin, &mut proc_stdout, open_mode) {
            Ok(()) => {
                remote.proc.stdin = Some(proc_stdin);
                remote.proc.stdout = Some(proc_stdout);
                return Ok(remote);
            }
            Err(err) => {
                if let Some(protocol::AbortError::ServerUnavailable { message, .. }) =
                    err.root_cause().downcast_ref()
                {
                    if retry_count == 1 {
                        // Print after the second retry so that DNS load balancing can resolve
                        // the problem if the server supports this.
                        progress.println(format!(
                            "server is unavailable ({}), retrying after delay.",
                            message
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_secs(retry_duration));
                    retry_duration = (retry_duration * 2).min(180);
                    retry_count += 1;
                    if retry_count < 50 {
                        continue;
                    }
                }
                return Err(err);
            }
        }
    }
}

fn cli_to_progress_bar(
    matches: &getopts::Matches,
    style: indicatif::ProgressStyle,
) -> indicatif::ProgressBar {
    let want_visible_progress = !matches.opt_present("quiet")
        && atty::is(atty::Stream::Stderr)
        && atty::is(atty::Stream::Stdout);
    let progress = indicatif::ProgressBar::with_draw_target(
        u64::MAX,
        if want_visible_progress {
            indicatif::ProgressDrawTarget::stderr()
        } else {
            indicatif::ProgressDrawTarget::hidden()
        },
    );
    progress.set_style(style);
    progress.set_message(&"connecting...");
    if want_visible_progress {
        progress.enable_steady_tick(250)
    };
    progress.tick();
    progress
}

fn help_main(args: Vec<String>) {
    let opts = default_cli_opts();
    print_help_and_exit(&args[0], &opts);
}

fn version_main(args: Vec<String>) -> Result<(), anyhow::Error> {
    let opts = default_cli_opts();
    parse_cli_opts(opts, &args[..]);
    writeln!(
        &mut std::io::stdout(),
        "bupstash-{}",
        env!("CARGO_PKG_VERSION"),
    )?;
    Ok(())
}

fn init_main(args: Vec<String>) -> Result<(), anyhow::Error> {
    let mut opts = default_cli_opts();
    repo_cli_opts(&mut opts);
    opts.optopt(
        "s",
        "storage",
        "The storage engine specification. 'dir', or a json specification. Consult the manual for details.",
        "STORAGE",
    );
    opts.optflag("q", "quiet", "Suppress progress indicators.");
    let matches = parse_cli_opts(opts, &args[..]);

    let storage_spec: Option<repository::StorageEngineSpec> = match matches.opt_str("storage") {
        Some(s) if s == "dir" => Some(repository::StorageEngineSpec::DirStore),
        Some(s) => match serde_json::from_str(&s) {
            Ok(s) => Some(s),
            Err(err) => anyhow::bail!("unable to parse storage engine spec: {}", err),
        },
        None => None,
    };

    let progress = cli_to_progress_bar(
        &matches,
        indicatif::ProgressStyle::default_spinner().template("[{elapsed_precise}] {wide_msg}"),
    );

    let mut serve_proc = cli_to_serve_process(&matches, &progress)?;
    let mut serve_out = serve_proc.proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.proc.stdin.as_mut().unwrap();

    client::init_repository(&mut serve_out, &mut serve_in, storage_spec)?;
    client::hangup(&mut serve_in)?;
    serve_proc.wait()?;

    Ok(())
}

enum ListFormat {
    Human,
    Jsonl1,
    Bare,
}

fn list_main(args: Vec<String>) -> Result<(), anyhow::Error> {
    let mut opts = default_cli_opts();
    repo_cli_opts(&mut opts);
    opts.optopt(
        "k",
        "key",
        "primary or metadata key to decrypt item metadata with during listing.",
        "PATH",
    );
    opts.optopt(
        "",
        "format",
        "Output format, valid values are 'human' or 'jsonl1'.",
        "FORMAT",
    );
    query_cli_opts(&mut opts);

    let matches = parse_cli_opts(opts, &args[..]);

    let list_format = match matches.opt_str("format") {
        Some(f) => match &f[..] {
            "jsonl1" => ListFormat::Jsonl1,
            "human" => ListFormat::Human,
            _ => anyhow::bail!("invalid --format, expected one of 'human' or 'jsonl1'"),
        },
        None => ListFormat::Human,
    };

    let (primary_key_id, metadata_dctx) = match cli_to_opt_key(&matches)? {
        Some(key) => {
            if !key.is_list_key() {
                anyhow::bail!(
                    "only main keys and sub keys created with '--list' can be used for listing"
                )
            }

            let primary_key_id = key.primary_key_id();
            let metadata_dctx = match key {
                keys::Key::PrimaryKeyV1(k) => {
                    crypto::DecryptionContext::new(k.metadata_sk, k.metadata_psk)
                }
                keys::Key::SubKeyV1(k) => {
                    crypto::DecryptionContext::new(k.metadata_sk.unwrap(), k.metadata_psk.unwrap())
                }
            };

            (Some(primary_key_id), Some(metadata_dctx))
        }
        None => {
            if !matches.opt_present("query-encrypted") {
                anyhow::bail!("please set --key, BUPSTASH_KEY, BUPSTASH_KEY_COMMAND or pass --query-encrypted");
            }
            (None, None)
        }
    };

    let query = if !matches.free.is_empty() {
        match query::parse(&matches.free.join("•")) {
            Ok(query) => Some(query),
            Err(e) => {
                query::report_parse_error(e);
                anyhow::bail!("query parse error");
            }
        }
    } else {
        None
    };

    let progress = cli_to_progress_bar(
        &matches,
        indicatif::ProgressStyle::default_spinner().template("[{elapsed_precise}] {wide_msg}"),
    );

    let mut query_cache = cli_to_query_cache(&matches)?;

    let mut serve_proc =
        cli_to_opened_serve_process(&matches, &progress, protocol::OpenMode::Read)?;
    let mut serve_out = serve_proc.proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.proc.stdin.as_mut().unwrap();

    client::sync(progress, &mut query_cache, &mut serve_out, &mut serve_in)?;
    client::hangup(&mut serve_in)?;
    serve_proc.wait()?;

    let out = std::io::stdout();
    let mut out = out.lock();

    let mut on_match =
        |item_id: xid::Xid,
         tags: &std::collections::BTreeMap<String, String>,
         metadata: &oplog::VersionedItemMetadata,
         secret_metadata: Option<&oplog::DecryptedItemMetadata>| {
            let mut tags: Vec<(&String, &String)> = tags.iter().collect();

            // Custom sort to be more human friendly.
            tags.sort_by(|(k1, _), (k2, _)| match (k1.as_str(), k2.as_str()) {
                ("id", _) => std::cmp::Ordering::Less,
                (_, "id") => std::cmp::Ordering::Greater,
                ("name", _) => std::cmp::Ordering::Less,
                (_, "name") => std::cmp::Ordering::Greater,
                _ => k1.partial_cmp(k2).unwrap(),
            });

            match list_format {
                ListFormat::Human => {
                    for (i, (k, v)) in tags.iter().enumerate() {
                        if i != 0 {
                            write!(out, " ")?;
                        }
                        write!(
                            out,
                            "{}=\"{}\"",
                            k,
                            v.replace("\\", "\\\\").replace("\"", "\\\"")
                        )?;
                    }
                    writeln!(out)?;
                }
                ListFormat::Jsonl1 => {
                    write!(out, "{{")?;
                    write!(
                        out,
                        "\"id\":{}",
                        serde_json::to_string(&item_id.to_string())?
                    )?;
                    write!(
                        out,
                        ",\"decryption_key_id\":{}",
                        serde_json::to_string(&metadata.primary_key_id().to_string())?
                    )?;
                    let data_tree = metadata.data_tree();
                    write!(out, ",\"data_tree\":{{")?;
                    write!(
                        out,
                        "\"address\":{}",
                        serde_json::to_string(&data_tree.address.to_string())?
                    )?;
                    write!(out, ",\"height\":{}", data_tree.height.0)?;
                    write!(
                        out,
                        ",\"data_chunk_count\":{}",
                        data_tree.data_chunk_count.0
                    )?;
                    write!(out, "}}")?;
                    if let Some(index_tree) = metadata.index_tree() {
                        write!(out, ",\"index_tree\":{{")?;
                        write!(
                            out,
                            "\"address\":{}",
                            serde_json::to_string(&index_tree.address.to_string())?
                        )?;
                        write!(out, ",\"height\":{}", index_tree.height.0)?;
                        write!(
                            out,
                            ",\"data_chunk_count\":{}",
                            index_tree.data_chunk_count.0
                        )?;
                        write!(out, "}}")?;
                    }
                    if let Some(secret_metadata) = secret_metadata {
                        write!(out, ",\"data_size\":{}", secret_metadata.data_size.0)?;
                        write!(out, ",\"index_size\":{}", secret_metadata.index_size.0)?;
                        write!(out, ",\"put_key_id\":\"{:x}\"", secret_metadata.send_key_id)?;
                        write!(
                            out,
                            ",\"data_hash_key_part\":\"{:x}\"",
                            secret_metadata.data_hash_key_part_2
                        )?;
                        write!(
                            out,
                            ",\"index_hash_key_part\":\"{:x}\"",
                            secret_metadata.index_hash_key_part_2
                        )?;
                    }
                    let unix_timestamp_millis = match metadata {
                        oplog::VersionedItemMetadata::V1(_) => {
                            if let Some(secret_metadata) = secret_metadata {
                                Some(secret_metadata.timestamp.timestamp_millis() as u64)
                            } else {
                                None
                            }
                        }
                        oplog::VersionedItemMetadata::V2(ref metadata) => {
                            Some(metadata.plain_text_metadata.unix_timestamp_millis)
                        }
                    };
                    if let Some(unix_timestamp_millis) = unix_timestamp_millis {
                        write!(out, ",\"unix_timestamp_millis\":{}", unix_timestamp_millis)?;
                    }
                    write!(out, ",\"tags\":{{")?;
                    for (i, (k, v)) in tags.iter().enumerate() {
                        if i != 0 {
                            write!(out, ", ")?;
                        }
                        write!(
                            out,
                            "{}:{}",
                            serde_json::to_string(&k)?,
                            serde_json::to_string(&v)?
                        )?;
                    }
                    writeln!(out, "}}")?;
                    writeln!(out, "}}")?;
                }
                ListFormat::Bare => anyhow::bail!("unsupported list format"),
            }

            Ok(())
        };

    let mut tx = query_cache.transaction()?;
    tx.list(
        querycache::ListOptions {
            primary_key_id,
            query,
            metadata_dctx,
            list_encrypted: matches.opt_present("query-encrypted"),
            utc_timestamps: matches.opt_present("utc-timestamps"),
            now: chrono::Utc::now(),
        },
        &mut on_match,
    )?;

    Ok(())
}

fn put_main(args: Vec<String>) -> Result<(), anyhow::Error> {
    let mut opts = default_cli_opts();
    repo_cli_opts(&mut opts);
    opts.optopt(
        "k",
        "key",
        "Primary or put key to encrypt data with.",
        "PATH",
    );
    opts.optflag("", "no-compression", "Disable data compression.");
    opts.optflag("", "no-default-tags", "Disable the default tag(s) 'name'.");
    opts.optflag(
        "",
        "print-stats",
        "Print put statistics to stderr on completion.",
    );
    opts.optflag("q", "quiet", "Suppress progress indicators.");

    opts.optflag(
        "e",
        "exec",
        "Treat arguments as a command to run, ensuring it succeeds before committing the item.",
    );
    opts.optflag(
        "",
        "no-stat-caching",
        "Do not use stat caching to skip sending files to the repository.",
    );
    opts.optflag(
        "",
        "no-send-log",
        "Disable logging of previously sent data, implies --no-stat-caching.",
    );
    opts.optflag("", "xattrs", "Save directory entry xattrs.");
    opts.optopt(
        "",
        "send-log",
        "Use the file at PATH as a 'send log', used to skip data that was previously sent to the repository.",
        "PATH",
    );
    opts.optmulti(
        "",
        "exclude",
        "Exclude directory entries matching the given glob pattern when saving a directory, may be passed multiple times.",
        "PATTERN",
    );
    opts.optflag(
        "",
        "one-file-system",
        "Do not cross mount points when traversing the file system.",
    );

    let matches = parse_cli_opts(opts, &args);

    let tag_re = regex::Regex::new(r"^([a-zA-Z0-9\\-_]+)=(.+)$").unwrap();

    let mut tags = BTreeMap::<String, String>::new();
    let mut source_args = Vec::new();

    {
        let mut collecting_tags = true;

        for a in &matches.free {
            if collecting_tags && a == "::" {
                collecting_tags = false;
                continue;
            }
            if collecting_tags {
                match tag_re.captures(&a) {
                    Some(caps) => {
                        let t = &caps[1];
                        let v = &caps[2];
                        tags.insert(t.to_string(), v.to_string());
                    }
                    None => {
                        collecting_tags = false;
                        source_args.push(a.to_string());
                    }
                }
            } else {
                source_args.push(a.to_string());
            }
        }
    }

    let want_xattrs = matches.opt_present("xattrs");

    let compression = if matches.opt_present("no-compression") {
        compression::Scheme::None
    } else {
        compression::Scheme::Lz4
    };

    let use_stat_cache =
        !(matches.opt_present("no-stat-caching") || matches.opt_present("no-send-log"));

    let mut exclusions = Vec::new();
    for e in matches.opt_strs("exclude") {
        match glob::Pattern::new(&e) {
            Ok(pattern) => exclusions.push(pattern),
            Err(err) => anyhow::bail!("--exclude option {:?} is not a valid glob: {}", e, err),
        }
    }

    let one_file_system = matches.opt_present("one-file-system");

    let checkpoint_bytes: u64 = match std::env::var("BUPSTASH_CHECKPOINT_BYTES") {
        Ok(v) => match v.parse() {
            Ok(v) => v,
            Err(err) => anyhow::bail!("unable to parse BUPSTASH_CHECKPOINT_BYTES: {}", err),
        },
        Err(_) => 21474836480,
    };

    let key = cli_to_key(&matches)?;

    if !key.is_put_key() {
        anyhow::bail!(
            "can only send data with a primary key or a sub key created with '--allow-put'."
        );
    }

    let primary_key_id = key.primary_key_id();
    let send_key_id = key.id();

    let (idx_hash_key, data_hash_key, gear_tab, data_ectx, metadata_ectx, idx_ectx) = match key {
        keys::Key::PrimaryKeyV1(k) => {
            let idx_hash_key =
                crypto::derive_hash_key(&k.idx_hash_key_part_1, &k.idx_hash_key_part_2);
            let data_hash_key =
                crypto::derive_hash_key(&k.data_hash_key_part_1, &k.data_hash_key_part_2);
            let gear_tab = k.rollsum_key.gear_tab();
            let data_ectx = crypto::EncryptionContext::new(&k.data_pk, &k.data_psk);
            let metadata_ectx = crypto::EncryptionContext::new(&k.metadata_pk, &k.metadata_psk);
            let idx_ectx = crypto::EncryptionContext::new(&k.idx_pk, &k.idx_psk);
            (
                idx_hash_key,
                data_hash_key,
                gear_tab,
                data_ectx,
                metadata_ectx,
                idx_ectx,
            )
        }
        keys::Key::SubKeyV1(k) => {
            let idx_hash_key = crypto::derive_hash_key(
                &k.idx_hash_key_part_1.unwrap(),
                &k.idx_hash_key_part_2.unwrap(),
            );
            let data_hash_key = crypto::derive_hash_key(
                &k.data_hash_key_part_1.unwrap(),
                &k.data_hash_key_part_2.unwrap(),
            );
            let gear_tab = k.rollsum_key.unwrap().gear_tab();
            let data_ectx =
                crypto::EncryptionContext::new(&k.data_pk.unwrap(), &k.data_psk.unwrap());
            let metadata_ectx =
                crypto::EncryptionContext::new(&k.metadata_pk.unwrap(), &k.metadata_psk.unwrap());
            let idx_ectx = crypto::EncryptionContext::new(&k.idx_pk.unwrap(), &k.idx_psk.unwrap());
            (
                idx_hash_key,
                data_hash_key,
                gear_tab,
                data_ectx,
                metadata_ectx,
                idx_ectx,
            )
        }
    };

    let default_tags = !matches.opt_present("no-default-tags");

    let mut data_source: client::DataSource;

    let progress = cli_to_progress_bar(
        &matches,
        indicatif::ProgressStyle::default_spinner()
            .template("[{elapsed_precise}] {wide_msg} [{bytes} sent, {bytes_per_sec}]"),
    );

    if matches.opt_present("exec") {
        data_source = client::DataSource::Subprocess(source_args)
    } else if source_args.is_empty() {
        anyhow::bail!("data sources should be a file, directory, or command (use '-' for stdin).");
    } else if source_args.len() == 1 {
        if source_args[0] == "-" {
            data_source = client::DataSource::Readable {
                description: "<stdin>".to_string(),
                data: Box::new(Box::new(std::io::stdin())),
            };
        } else {
            let input_path: std::path::PathBuf = std::convert::From::from(&source_args[0]);
            let input_path = std::fs::canonicalize(&input_path)?;

            let md = match std::fs::metadata(&input_path) {
                Ok(md) => md,
                Err(err) => anyhow::bail!("unable to put {:?}: {}", input_path, err),
            };

            let name = match input_path.file_name() {
                Some(name) => name.to_string_lossy().to_string(),
                None => "rootfs".to_string(),
            };

            if md.is_dir() {
                if default_tags {
                    tags.insert("name".to_string(), name + ".tar");
                }

                data_source = client::DataSource::Filesystem {
                    base: input_path.clone(),
                    paths: vec![input_path],
                    exclusions,
                };
            } else if md.is_file() {
                if default_tags {
                    tags.insert("name".to_string(), name);
                }

                data_source = client::DataSource::Readable {
                    description: input_path.to_string_lossy().to_string(),
                    data: Box::new(std::fs::File::open(input_path)?),
                };
            } else {
                anyhow::bail!("{} is not a file or a directory", source_args[0]);
            }
        }
    } else {
        // Gather absolute paths.
        let mut canonicalized = Vec::new();
        for input_path in source_args.iter() {
            let input_path = match std::fs::canonicalize(input_path) {
                Ok(p) => p,
                Err(err) => anyhow::bail!("unable to put {:?}: {}", input_path, err),
            };
            canonicalized.push(input_path)
        }
        canonicalized.sort();
        canonicalized.dedup();
        // Prune away paths that encapsulate eachother, for example
        // 'put /a /a/b'  is really just 'put /a'.
        let mut pruned_paths = Vec::new();
        let mut i = 0;
        while i < canonicalized.len() {
            let mut j = i + 1;
            loop {
                match (&canonicalized[i], canonicalized.get(j)) {
                    (_, None) => break,
                    (a, Some(b)) => {
                        if fsutil::common_path(a, b).unwrap() != *a {
                            break;
                        }
                    }
                }
                j += 1;
            }
            pruned_paths.push(canonicalized[i].clone());
            i = j;
        }

        // We should always have at least "/" in common.
        let base_path = fsutil::common_path_all(&pruned_paths).unwrap();

        if default_tags {
            let name = match base_path.file_name() {
                Some(name) => name.to_string_lossy().to_string() + ".tar",
                None => "rootfs.tar".to_string(),
            };

            tags.insert("name".to_string(), name);
        }

        data_source = client::DataSource::Filesystem {
            base: base_path,
            paths: pruned_paths,
            exclusions,
        };
    };

    // No easy way to compute the tag set length without actually encoding it due
    // to var ints in the bare encoding.
    if serde_bare::to_vec(&tags)?.len() > oplog::MAX_TAG_SET_SIZE {
        anyhow::bail!("tags must not exceed {} bytes", oplog::MAX_TAG_SET_SIZE);
    }

    let send_log = if matches.opt_present("no-send-log") {
        None
    } else {
        progress.set_message(&"acquiring exclusive lock on send-log...");
        match matches.opt_str("send-log") {
            Some(send_log) => Some(sendlog::SendLog::open(&std::path::PathBuf::from(send_log))?),
            None => match std::env::var_os("BUPSTASH_SEND_LOG") {
                Some(send_log) => {
                    Some(sendlog::SendLog::open(&std::path::PathBuf::from(send_log))?)
                }
                None => {
                    let mut p = cache_dir()?;
                    std::fs::create_dir_all(&p)?;
                    p.push("bupstash.sendlog");
                    Some(sendlog::SendLog::open(&p)?)
                }
            },
        }
    };

    let mut serve_proc =
        cli_to_opened_serve_process(&matches, &progress, protocol::OpenMode::ReadWrite)?;
    let mut serve_out = serve_proc.proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.proc.stdin.as_mut().unwrap();
    let mut ctx = client::SendContext {
        progress: progress.clone(),
        compression,
        checkpoint_bytes,
        use_stat_cache,
        primary_key_id,
        send_key_id,
        gear_tab,
        data_hash_key,
        data_ectx,
        metadata_ectx,
        idx_hash_key,
        idx_ectx,
        want_xattrs,
        one_file_system,
    };

    let (id, stats) = client::send(
        &mut ctx,
        &mut serve_out,
        &mut serve_in,
        send_log,
        tags,
        &mut data_source,
    )?;
    client::hangup(&mut serve_in)?;
    serve_proc.wait()?;

    progress.finish_and_clear();

    if matches.opt_present("print-stats") {
        let duration = stats.end_time.signed_duration_since(stats.start_time);
        let total_uncompressed_size = stats.uncompressed_data_size + stats.uncompressed_index_size;
        writeln!(
            std::io::stderr(),
            "{}m{}.{}s put duration",
            duration.num_minutes(),
            duration.num_seconds() % 60,
            duration.num_milliseconds() % 1000
        )?;
        writeln!(
            std::io::stderr(),
            "{} chunk(s), {} processed",
            stats.total_chunks,
            fmtutil::format_size(total_uncompressed_size)
        )?;
        writeln!(
            std::io::stderr(),
            "{} chunk(s), {} (compressed) sent",
            stats.transferred_chunks,
            fmtutil::format_size(stats.transferred_bytes),
        )?;
        writeln!(
            std::io::stderr(),
            "{} chunk(s), {} (compressed) added",
            stats.added_chunks,
            fmtutil::format_size(stats.added_bytes)
        )?;
        if stats.added_bytes == 0 {
            writeln!(std::io::stderr(), "infinite effective compression ratio")?;
        } else {
            let ecr = (total_uncompressed_size as f64) / (stats.added_bytes as f64);
            writeln!(
                std::io::stderr(),
                "{:.1}:1 effective compression ratio",
                ecr
            )?;
        }
    }

    writeln!(std::io::stdout(), "{:x}", id)?;
    Ok(())
}

fn get_main(args: Vec<String>) -> Result<(), anyhow::Error> {
    let mut opts = default_cli_opts();
    repo_cli_opts(&mut opts);
    query_cli_opts(&mut opts);
    opts.optopt("k", "key", "Key to decrypt data with.", "PATH");
    opts.optopt(
        "",
        "pick",
        "Pick a single file or directory from a directory snapshot.",
        "PATH",
    );

    let matches = parse_cli_opts(opts, &args[..]);

    let key = cli_to_key(&matches)?;
    let primary_key_id = key.primary_key_id();
    let (idx_hash_key_part_1, data_hash_key_part_1, data_dctx, metadata_dctx, idx_dctx) = match key
    {
        keys::Key::PrimaryKeyV1(k) => {
            let idx_hash_key_part_1 = k.idx_hash_key_part_1.clone();
            let data_hash_key_part_1 = k.data_hash_key_part_1.clone();
            let data_dctx = crypto::DecryptionContext::new(k.data_sk, k.data_psk.clone());
            let metadata_dctx = crypto::DecryptionContext::new(k.metadata_sk, k.metadata_psk);
            let idx_dctx = crypto::DecryptionContext::new(k.idx_sk, k.idx_psk);
            (
                idx_hash_key_part_1,
                data_hash_key_part_1,
                data_dctx,
                metadata_dctx,
                idx_dctx,
            )
        }
        _ => anyhow::bail!("provided key is not a data decryption key"),
    };

    let progress = cli_to_progress_bar(
        &matches,
        indicatif::ProgressStyle::default_spinner().template("[{elapsed_precise}] {wide_msg}"),
    );

    let (id, query) = cli_to_id_and_query(&matches)?;
    let mut serve_proc =
        cli_to_opened_serve_process(&matches, &progress, protocol::OpenMode::Read)?;
    let mut serve_out = serve_proc.proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.proc.stdin.as_mut().unwrap();

    let id = match (id, query) {
        (Some(id), _) => id,
        (_, query) => {
            let mut query_cache = cli_to_query_cache(&matches)?;

            // Only sync the client if we have a non id query.
            client::sync(
                progress.clone(),
                &mut query_cache,
                &mut serve_out,
                &mut serve_in,
            )?;

            let mut n_matches: u64 = 0;
            let mut id = xid::Xid::default();

            let mut on_match =
                |item_id: xid::Xid,
                 _tags: &std::collections::BTreeMap<String, String>,
                 _metadata: &oplog::VersionedItemMetadata,
                 _secret_metadata: Option<&oplog::DecryptedItemMetadata>| {
                    n_matches += 1;
                    id = item_id;

                    if n_matches > 1 {
                        anyhow::bail!(
                            "the provided query matched {} items, need a single match",
                            n_matches
                        );
                    }

                    Ok(())
                };

            let mut tx = query_cache.transaction()?;
            tx.list(
                querycache::ListOptions {
                    primary_key_id: Some(primary_key_id),
                    metadata_dctx: Some(metadata_dctx.clone()),
                    list_encrypted: matches.opt_present("query-encrypted"),
                    utc_timestamps: matches.opt_present("utc-timestamps"),
                    query: Some(query),
                    now: chrono::Utc::now(),
                },
                &mut on_match,
            )?;

            id
        }
    };

    progress.set_message("fetching item metadata...");
    let metadata = client::request_metadata(id, &mut serve_out, &mut serve_in)?;

    let mut content_index = if metadata.index_tree().is_some() {
        Some(client::request_index(
            client::IndexRequestContext {
                primary_key_id,
                idx_hash_key_part_1,
                idx_dctx,
                metadata_dctx: metadata_dctx.clone(),
            },
            id,
            &metadata,
            &mut serve_out,
            &mut serve_in,
        )?)
    } else {
        None
    };

    let pick = if matches.opt_present("pick") {
        progress.set_message("fetching content index...");

        if let Some(ref content_index) = content_index {
            Some(index::pick(
                &matches.opt_str("pick").unwrap(),
                content_index,
            )?)
        } else {
            anyhow::bail!("requested item does not have a content index (tarball was not created by bupstash)")
        }
    } else {
        None
    };

    // The pick contains a sub-index, explicitly drop the content index.
    if pick.is_some() {
        content_index = None;
    }

    progress.finish_and_clear();

    client::request_data_stream(
        client::DataRequestContext {
            primary_key_id,
            data_dctx,
            metadata_dctx,
            data_hash_key_part_1,
        },
        id,
        &metadata,
        pick,
        content_index,
        &mut serve_out,
        &mut serve_in,
        &mut std::io::stdout().lock(),
    )?;

    client::hangup(&mut serve_in)?;
    serve_proc.wait()?;

    Ok(())
}

fn format_human_content_listing(
    ent: &index::IndexEntry,
    utc_timestamps: bool,
    pad_size_to: usize,
) -> String {
    let mut result = String::new();
    std::fmt::write(&mut result, format_args!("{}", ent.display_mode())).unwrap();
    let size = if ent.is_file() {
        fmtutil::format_size(ent.size.0)
    } else {
        "-".to_string()
    };
    let size_padding: String = std::iter::repeat(' ')
        .take(pad_size_to - size.len())
        .collect();
    std::fmt::write(&mut result, format_args!(" {}{}", size, size_padding)).unwrap();
    let ts = chrono::NaiveDateTime::from_timestamp(ent.ctime.0 as i64, ent.ctime_nsec.0 as u32);
    let ts = chrono::DateTime::<chrono::Utc>::from_utc(ts, chrono::Utc);
    let ts = fmtutil::format_timestamp(&ts, utc_timestamps);
    std::fmt::write(&mut result, format_args!(" {}", ts)).unwrap();
    std::fmt::write(&mut result, format_args!(" {}", ent.path)).unwrap();
    result
}

fn format_jsonl1_content_listing(ent: &index::IndexEntry) -> Result<String, anyhow::Error> {
    let mut result = String::new();
    std::fmt::write(&mut result, format_args!("{{"))?;
    std::fmt::write(
        &mut result,
        format_args!("\"mode\":{}", serde_json::to_string(&ent.mode.0)?),
    )?;
    std::fmt::write(&mut result, format_args!(",\"size\":{}", ent.size.0))?;
    std::fmt::write(
        &mut result,
        format_args!(",\"path\":{}", serde_json::to_string(&ent.path)?),
    )?;
    std::fmt::write(
        &mut result,
        format_args!(",\"mtime\":{}", serde_json::to_string(&ent.mtime.0)?),
    )?;
    std::fmt::write(
        &mut result,
        format_args!(
            ",\"mtime_nsec\":{}",
            serde_json::to_string(&ent.mtime_nsec.0)?
        ),
    )?;
    std::fmt::write(
        &mut result,
        format_args!(",\"ctime\":{}", serde_json::to_string(&ent.ctime.0)?),
    )?;
    std::fmt::write(
        &mut result,
        format_args!(
            ",\"ctime_nsec\":{}",
            serde_json::to_string(&ent.ctime_nsec.0)?
        ),
    )?;
    std::fmt::write(
        &mut result,
        format_args!(",\"uid\":{}", serde_json::to_string(&ent.uid.0)?),
    )?;
    std::fmt::write(
        &mut result,
        format_args!(",\"gid\":{}", serde_json::to_string(&ent.gid.0)?),
    )?;
    std::fmt::write(
        &mut result,
        format_args!(",\"norm_dev\":{}", serde_json::to_string(&ent.norm_dev.0)?),
    )?;
    std::fmt::write(
        &mut result,
        format_args!(",\"nlink\":{}", serde_json::to_string(&ent.nlink.0)?),
    )?;
    if ent.is_dev_node() {
        std::fmt::write(
            &mut result,
            format_args!(
                ",\"dev_major\":{}",
                serde_json::to_string(&ent.dev_major.0)?
            ),
        )?;
        std::fmt::write(
            &mut result,
            format_args!(
                ",\"dev_minor\":{}",
                serde_json::to_string(&ent.dev_minor.0)?
            ),
        )?;
    }
    if let Some(ref xattrs) = ent.xattrs {
        std::fmt::write(
            &mut result,
            format_args!(",\"xattrs\":{}", serde_json::to_string(xattrs)?),
        )?;
    }
    if let Some(ref link_target) = ent.link_target {
        std::fmt::write(
            &mut result,
            format_args!(",\"link_target\":{}", serde_json::to_string(link_target)?),
        )?;
    }
    match ent.data_hash {
        index::ContentCryptoHash::None => (),
        index::ContentCryptoHash::Blake3(h) => std::fmt::write(
            &mut result,
            format_args!(
                ",\"data_hash\":{}",
                serde_json::to_string(&format!("blake3:{}", hex::easy_encode_to_string(&h)))?
            ),
        )?,
    };
    std::fmt::write(&mut result, format_args!("}}"))?;
    Ok(result)
}

fn list_contents_main(args: Vec<String>) -> Result<(), anyhow::Error> {
    let mut opts = default_cli_opts();
    repo_cli_opts(&mut opts);
    query_cli_opts(&mut opts);
    opts.optopt("k", "key", "Key to decrypt data with.", "PATH");
    opts.optopt(
        "",
        "format",
        "Output format, valid values are 'human' or 'jsonl1'.",
        "FORMAT",
    );

    let matches = parse_cli_opts(opts, &args[..]);

    let list_format = match matches.opt_str("format") {
        Some(f) => match &f[..] {
            "jsonl1" => ListFormat::Jsonl1,
            "human" => ListFormat::Human,
            "BARE" => ListFormat::Bare,
            _ => anyhow::bail!("invalid --format, expected one of 'human' or 'jsonl1'"),
        },
        None => ListFormat::Human,
    };

    let key = cli_to_key(&matches)?;

    if !key.is_list_key() || !key.is_list_contents_key() {
        anyhow::bail!(
            "only primary keys and sub keys created with '--list-contents' can list contents"
        );
    }

    let primary_key_id = key.primary_key_id();
    let (idx_hash_key_part_1, metadata_dctx, idx_dctx) = match key {
        keys::Key::PrimaryKeyV1(k) => {
            let idx_hash_key_part_1 = k.idx_hash_key_part_1.clone();
            let metadata_dctx = crypto::DecryptionContext::new(k.metadata_sk, k.metadata_psk);
            let idx_dctx = crypto::DecryptionContext::new(k.idx_sk, k.idx_psk);
            (idx_hash_key_part_1, metadata_dctx, idx_dctx)
        }
        keys::Key::SubKeyV1(k) => {
            let idx_hash_key_part_1 = k.idx_hash_key_part_1.unwrap();
            let metadata_dctx =
                crypto::DecryptionContext::new(k.metadata_sk.unwrap(), k.metadata_psk.unwrap());
            let idx_dctx = crypto::DecryptionContext::new(k.idx_sk.unwrap(), k.idx_psk.unwrap());
            (idx_hash_key_part_1, metadata_dctx, idx_dctx)
        }
    };

    let progress = cli_to_progress_bar(
        &matches,
        indicatif::ProgressStyle::default_spinner().template("[{elapsed_precise}] {wide_msg}"),
    );

    let (id, query) = cli_to_id_and_query(&matches)?;
    let mut serve_proc =
        cli_to_opened_serve_process(&matches, &progress, protocol::OpenMode::Read)?;
    let mut serve_out = serve_proc.proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.proc.stdin.as_mut().unwrap();

    let id = match (id, query) {
        (Some(id), _) => id,
        (_, query) => {
            let mut query_cache = cli_to_query_cache(&matches)?;

            // Only sync the client if we have a non id query.
            client::sync(
                progress.clone(),
                &mut query_cache,
                &mut serve_out,
                &mut serve_in,
            )?;

            let mut n_matches: u64 = 0;
            let mut id = xid::Xid::default();

            let mut on_match =
                |item_id: xid::Xid,
                 _tags: &std::collections::BTreeMap<String, String>,
                 _metadata: &oplog::VersionedItemMetadata,
                 _secret_metadata: Option<&oplog::DecryptedItemMetadata>| {
                    n_matches += 1;
                    id = item_id;

                    if n_matches > 1 {
                        anyhow::bail!(
                            "the provided query matched {} items, need a single match",
                            n_matches
                        );
                    }

                    Ok(())
                };

            let mut tx = query_cache.transaction()?;
            tx.list(
                querycache::ListOptions {
                    primary_key_id: Some(primary_key_id),
                    metadata_dctx: Some(metadata_dctx.clone()),
                    list_encrypted: matches.opt_present("query-encrypted"),
                    utc_timestamps: matches.opt_present("utc-timestamps"),
                    query: Some(query),
                    now: chrono::Utc::now(),
                },
                &mut on_match,
            )?;

            id
        }
    };

    progress.set_message("fetching item metadata...");
    let metadata = client::request_metadata(id, &mut serve_out, &mut serve_in)?;

    if metadata.index_tree().is_none() {
        anyhow::bail!(
            "list-contents is only supported for directory snapshots created by bupstash"
        );
    }

    progress.set_message("fetching content index...");
    let content_index = client::request_index(
        client::IndexRequestContext {
            primary_key_id,
            idx_hash_key_part_1,
            metadata_dctx,
            idx_dctx,
        },
        id,
        &metadata,
        &mut serve_out,
        &mut serve_in,
    )?;

    client::hangup(&mut serve_in)?;
    serve_proc.wait()?;

    progress.finish_and_clear();

    let utc_timestamps = matches.opt_present("utc-timestamps");

    let out = std::io::stdout();
    let mut out = out.lock();

    match list_format {
        ListFormat::Human => {
            let mut max_size_digits = 0;
            for ent in content_index.iter() {
                let ent = ent?;
                max_size_digits =
                    std::cmp::max(fmtutil::format_size(ent.size.0).len(), max_size_digits)
            }
            for ent in content_index.iter() {
                let ent = ent?;
                writeln!(
                    out,
                    "{}",
                    format_human_content_listing(&ent, utc_timestamps, max_size_digits),
                )?;
            }
        }
        ListFormat::Jsonl1 => {
            for ent in content_index.iter() {
                let ent = ent?;
                writeln!(out, "{}", format_jsonl1_content_listing(&ent)?)?;
            }
        }
        ListFormat::Bare => {
            for ent in content_index.iter() {
                let ent = ent?;
                out.write_all(&serde_bare::to_vec(&ent)?)?;
            }
        }
    }

    out.flush()?;

    Ok(())
}

fn diff_main(args: Vec<String>) -> Result<(), anyhow::Error> {
    let mut opts = default_cli_opts();
    repo_cli_opts(&mut opts);
    query_cli_opts(&mut opts);
    opts.optopt("k", "key", "Key to decrypt data with.", "PATH");
    opts.optopt(
        "i",
        "ignore",
        "Comma separated list of file attributes to ignore in comparisons. Valid items are 'content,times,mode'.",
        "IGNORE",
    );
    opts.optopt(
        "",
        "format",
        "Output format, valid values are 'human' or 'jsonl'.",
        "FORMAT",
    );

    let matches = parse_cli_opts(opts, &args[..]);
    let utc_timestamps = matches.opt_present("utc-timestamps");
    let list_format = match matches.opt_str("format") {
        Some(f) => match &f[..] {
            "jsonl1" => ListFormat::Jsonl1,
            "human" => ListFormat::Human,
            _ => anyhow::bail!("invalid --format, expected one of 'human' or 'jsonl'"),
        },
        None => ListFormat::Human,
    };
    let mut diff_mask = index::INDEX_COMPARE_MASK_OFFSETS;

    if let Some(ignore) = matches.opt_str("ignore") {
        for ignore in ignore.split(',') {
            match ignore {
                "mode" => diff_mask |= index::INDEX_COMPARE_MASK_MODE,
                "content" => {
                    diff_mask |=
                        index::INDEX_COMPARE_MASK_SIZE | index::INDEX_COMPARE_MASK_DATA_HASH
                }
                "times" => {
                    diff_mask |= index::INDEX_COMPARE_MASK_MTIME | index::INDEX_COMPARE_MASK_CTIME
                }
                _ => anyhow::bail!("'{}' is not a valid ignore value", ignore),
            }
        }
    }

    let mut queries = vec![vec![]];
    {
        for a in &matches.free {
            if a == "::" {
                queries.push(vec![]);
                continue;
            }
            queries.last_mut().unwrap().push(a.to_string());
        }

        if queries.len() != 2 {
            anyhow::bail!("expected two queries separated by '::'");
        }
    }

    let key = cli_to_key(&matches)?;

    if !key.is_list_key() || !key.is_list_contents_key() {
        anyhow::bail!(
            "only primary keys and sub keys created with '--list-contents' can diff contents"
        );
    }

    let primary_key_id = key.primary_key_id();
    let (idx_hash_key_part_1, metadata_dctx, idx_dctx) = match key {
        keys::Key::PrimaryKeyV1(k) => {
            let idx_hash_key_part_1 = k.idx_hash_key_part_1.clone();
            let metadata_dctx = crypto::DecryptionContext::new(k.metadata_sk, k.metadata_psk);
            let idx_dctx = crypto::DecryptionContext::new(k.idx_sk, k.idx_psk);
            (idx_hash_key_part_1, metadata_dctx, idx_dctx)
        }
        keys::Key::SubKeyV1(k) => {
            let idx_hash_key_part_1 = k.idx_hash_key_part_1.unwrap();
            let metadata_dctx =
                crypto::DecryptionContext::new(k.metadata_sk.unwrap(), k.metadata_psk.unwrap());
            let idx_dctx = crypto::DecryptionContext::new(k.idx_sk.unwrap(), k.idx_psk.unwrap());
            (idx_hash_key_part_1, metadata_dctx, idx_dctx)
        }
    };

    let progress = cli_to_progress_bar(
        &matches,
        indicatif::ProgressStyle::default_spinner().template("[{elapsed_precise}] {wide_msg}"),
    );

    let mut serve_proc =
        cli_to_opened_serve_process(&matches, &progress, protocol::OpenMode::Read)?;
    let mut serve_out = serve_proc.proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.proc.stdin.as_mut().unwrap();

    let mut to_diff = vec![];

    for query in queries {
        let (id, query) = match query::parse(&query.join("•")) {
            Ok(query) => (query::get_id_query(&query), query),
            Err(e) => {
                query::report_parse_error(e);
                anyhow::bail!("query parse error");
            }
        };

        let id = match (id, query) {
            (Some(id), _) => id,
            (_, query) => {
                let mut query_cache = cli_to_query_cache(&matches)?;

                // Only sync the client if we have a non id query.
                client::sync(
                    progress.clone(),
                    &mut query_cache,
                    &mut serve_out,
                    &mut serve_in,
                )?;

                let mut n_matches: u64 = 0;
                let mut id = xid::Xid::default();

                let mut on_match =
                    |item_id: xid::Xid,
                     _tags: &std::collections::BTreeMap<String, String>,
                     _metadata: &oplog::VersionedItemMetadata,
                     _secret_metadata: Option<&oplog::DecryptedItemMetadata>| {
                        n_matches += 1;
                        id = item_id;

                        if n_matches > 1 {
                            anyhow::bail!(
                                "provided query matched {} items, need a single match",
                                n_matches
                            );
                        }

                        Ok(())
                    };

                let mut tx = query_cache.transaction()?;
                tx.list(
                    querycache::ListOptions {
                        primary_key_id: Some(primary_key_id),
                        metadata_dctx: Some(metadata_dctx.clone()),
                        list_encrypted: matches.opt_present("query-encrypted"),
                        query: Some(query),
                        now: chrono::Utc::now(),
                        utc_timestamps,
                    },
                    &mut on_match,
                )?;

                id
            }
        };

        progress.set_message("fetching item metadata...");
        let metadata = client::request_metadata(id, &mut serve_out, &mut serve_in)?;

        if metadata.index_tree().is_none() {
            anyhow::bail!("diff is only supported for directory snapshots created by bupstash");
        }

        progress.set_message("fetching content index...");
        let content_index = client::request_index(
            client::IndexRequestContext {
                primary_key_id,
                idx_hash_key_part_1: idx_hash_key_part_1.clone(),
                metadata_dctx: metadata_dctx.clone(),
                idx_dctx: idx_dctx.clone(),
            },
            id,
            &metadata,
            &mut serve_out,
            &mut serve_in,
        )?;

        to_diff.push(content_index);
    }

    client::hangup(&mut serve_in)?;
    serve_proc.wait()?;

    progress.finish_and_clear();

    let out = std::io::stdout();
    let mut out = out.lock();

    match list_format {
        ListFormat::Human => {
            let mut max_size_digits = 1;
            // Can we avoid walking twice?
            index::diff(
                &to_diff[0],
                &to_diff[1],
                diff_mask,
                &mut |_: char, e: &index::IndexEntry| -> Result<(), anyhow::Error> {
                    max_size_digits =
                        std::cmp::max(fmtutil::format_size(e.size.0).len(), max_size_digits);
                    Ok(())
                },
            )?;
            index::diff(
                &to_diff[0],
                &to_diff[1],
                diff_mask,
                &mut |op: char, e: &index::IndexEntry| -> Result<(), anyhow::Error> {
                    writeln!(
                        std::io::stdout(),
                        "{} {}",
                        op,
                        format_human_content_listing(e, utc_timestamps, max_size_digits)
                    )?;
                    Ok(())
                },
            )?;
        }
        ListFormat::Jsonl1 => {
            index::diff(
                &to_diff[0],
                &to_diff[1],
                diff_mask,
                &mut |op: char, e: &index::IndexEntry| -> Result<(), anyhow::Error> {
                    writeln!(
                        std::io::stdout(),
                        "{} {}",
                        op,
                        format_jsonl1_content_listing(e)?
                    )?;
                    Ok(())
                },
            )?;
        }
        ListFormat::Bare => {
            anyhow::bail!("unsupported diff format");
        }
    }

    out.flush()?;

    Ok(())
}

fn remove_main(args: Vec<String>) -> Result<(), anyhow::Error> {
    let mut opts = default_cli_opts();
    repo_cli_opts(&mut opts);
    query_cli_opts(&mut opts);

    opts.optopt("k", "key", "Key to decrypt metadata with.", "PATH");

    opts.optflag(
        "",
        "ids-from-stdin",
        "Remove items with IDs read from stdin, one per line, instead of executing a query.",
    );

    opts.optflag("", "allow-many", "Allow multiple removals.");

    let matches = parse_cli_opts(opts, &args[..]);

    let progress = cli_to_progress_bar(
        &matches,
        indicatif::ProgressStyle::default_spinner().template("[{elapsed_precise}] {wide_msg}"),
    );

    let n_removed;

    if matches.opt_present("ids-from-stdin") {
        let mut ids = Vec::new();

        for l in std::io::stdin().lock().lines() {
            let l = l?;
            if l.is_empty() {
                continue;
            }
            match xid::Xid::parse(&l) {
                Ok(id) => ids.push(id),
                Err(err) => anyhow::bail!("error id parsing {:?}: {}", l, err),
            };
        }

        n_removed = ids.len();

        let mut serve_proc =
            cli_to_opened_serve_process(&matches, &progress, protocol::OpenMode::ReadWrite)?;
        let mut serve_out = serve_proc.proc.stdout.as_mut().unwrap();
        let mut serve_in = serve_proc.proc.stdin.as_mut().unwrap();

        client::remove(progress.clone(), ids, &mut serve_out, &mut serve_in)?;
        client::hangup(&mut serve_in)?;
        serve_proc.wait()?;
    } else {
        let mut serve_proc =
            cli_to_opened_serve_process(&matches, &progress, protocol::OpenMode::ReadWrite)?;
        let mut serve_out = serve_proc.proc.stdout.as_mut().unwrap();
        let mut serve_in = serve_proc.proc.stdin.as_mut().unwrap();

        let ids: Vec<xid::Xid> = match cli_to_id_and_query(&matches)? {
            (Some(id), _) => vec![id],
            (_, query) => {
                let mut query_cache = cli_to_query_cache(&matches)?;

                // Only sync the client if we have a non id query.
                client::sync(
                    progress.clone(),
                    &mut query_cache,
                    &mut serve_out,
                    &mut serve_in,
                )?;

                let (primary_key_id, metadata_dctx) = match cli_to_opt_key(&matches)? {
                    Some(key) => {
                        if !key.is_list_key() {
                            anyhow::bail!("only primary keys and sub keys created with '--list' can be used for listing")
                        }

                        let primary_key_id = key.primary_key_id();
                        let metadata_dctx = match key {
                            keys::Key::PrimaryKeyV1(k) => {
                                crypto::DecryptionContext::new(k.metadata_sk, k.metadata_psk)
                            }
                            keys::Key::SubKeyV1(k) => crypto::DecryptionContext::new(
                                k.metadata_sk.unwrap(),
                                k.metadata_psk.unwrap(),
                            ),
                        };

                        (Some(primary_key_id), Some(metadata_dctx))
                    }
                    None => {
                        if !matches.opt_present("query-encrypted") {
                            anyhow::bail!("please set --key, BUPSTASH_KEY, BUPSTASH_KEY_COMMAND or pass --query-encrypted");
                        }
                        (None, None)
                    }
                };

                let mut ids = Vec::new();

                let mut on_match =
                    |item_id: xid::Xid,
                     _tags: &std::collections::BTreeMap<String, String>,
                     _metadata: &oplog::VersionedItemMetadata,
                     _secret_metadata: Option<&oplog::DecryptedItemMetadata>| {
                        ids.push(item_id);
                        Ok(())
                    };

                let mut tx = query_cache.transaction()?;
                tx.list(
                    querycache::ListOptions {
                        primary_key_id,
                        metadata_dctx,
                        list_encrypted: matches.opt_present("query-encrypted"),
                        utc_timestamps: matches.opt_present("utc-timestamps"),
                        query: Some(query),
                        now: chrono::Utc::now(),
                    },
                    &mut on_match,
                )?;

                if ids.len() > 1 && !matches.opt_present("allow-many") {
                    anyhow::bail!(
                        "the provided query matched {} items, need a single match unless --allow-many is specified",
                        ids.len()
                    );
                };

                ids
            }
        };
        n_removed = ids.len();
        client::remove(progress.clone(), ids, &mut serve_out, &mut serve_in)?;
        client::hangup(&mut serve_in)?;
        serve_proc.wait()?;
    };

    progress.finish_and_clear();

    writeln!(std::io::stdout(), "{} item(s) removed", n_removed)?;

    Ok(())
}

fn gc_main(args: Vec<String>) -> Result<(), anyhow::Error> {
    let mut opts = default_cli_opts();
    opts.optflag("q", "quiet", "Suppress progress indicators.");

    repo_cli_opts(&mut opts);
    let matches = parse_cli_opts(opts, &args[..]);

    let progress = cli_to_progress_bar(
        &matches,
        indicatif::ProgressStyle::default_spinner().template("[{elapsed_precise}] {wide_msg}"),
    );

    let mut serve_proc = cli_to_opened_serve_process(&matches, &progress, protocol::OpenMode::Gc)?;
    let mut serve_out = serve_proc.proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.proc.stdin.as_mut().unwrap();

    let stats = client::gc(progress.clone(), &mut serve_out, &mut serve_in)?;
    client::hangup(&mut serve_in)?;
    serve_proc.wait()?;

    progress.finish_and_clear();

    let out = std::io::stdout();
    let mut out = out.lock();

    if let Some(chunks_deleted) = stats.chunks_deleted {
        writeln!(out, "{} chunks deleted", chunks_deleted)?;
    }
    if let Some(chunks_remaining) = stats.chunks_remaining {
        writeln!(out, "{} chunks remaining", chunks_remaining)?;
    }
    if let Some(bytes_deleted) = stats.bytes_deleted {
        writeln!(out, "{} deleted", fmtutil::format_size(bytes_deleted))?;
    }
    if let Some(bytes_remaining) = stats.bytes_remaining {
        writeln!(out, "{} remaining", fmtutil::format_size(bytes_remaining))?;
    }

    Ok(())
}

fn restore_removed(args: Vec<String>) -> Result<(), anyhow::Error> {
    let mut opts = default_cli_opts();
    opts.optflag("q", "quiet", "Suppress progress indicators.");

    repo_cli_opts(&mut opts);
    let matches = parse_cli_opts(opts, &args[..]);

    let progress = cli_to_progress_bar(
        &matches,
        indicatif::ProgressStyle::default_spinner().template("[{elapsed_precise}] {wide_msg}"),
    );

    let mut serve_proc =
        cli_to_opened_serve_process(&matches, &progress, protocol::OpenMode::ReadWrite)?;
    let mut serve_out = serve_proc.proc.stdout.as_mut().unwrap();
    let mut serve_in = serve_proc.proc.stdin.as_mut().unwrap();

    let n_restored = client::restore_removed(progress.clone(), &mut serve_out, &mut serve_in)?;
    client::hangup(&mut serve_in)?;
    serve_proc.wait()?;

    progress.finish_and_clear();

    writeln!(std::io::stdout(), "{} item(s) restored", n_restored)?;

    Ok(())
}

fn put_benchmark(args: Vec<String>) -> Result<(), anyhow::Error> {
    let mut opts = default_cli_opts();
    opts.optflag("", "chunk", "Do rollsum chunking.");
    opts.optflag("", "compress", "Compress chunks.");
    opts.optflag("", "address", "Compute chunk content addresses.");
    opts.optflag("", "encrypt", "Encrypt chunks.");
    opts.optflag("", "print", "Print data to stdout.");
    opts.optflag("", "print-chunk-size", "Print chunk sizes.");

    let matches = parse_cli_opts(opts, &args[..]);

    let do_chunking = matches.opt_present("chunk");
    let do_compress = matches.opt_present("compress");
    let do_address = matches.opt_present("address");
    let do_encrypt = matches.opt_present("encrypt");
    let do_print = matches.opt_present("print");
    let do_print_chunk_size = matches.opt_present("print-chunk-size");

    let min_size = client::CHUNK_MIN_SIZE;
    let max_size = client::CHUNK_MAX_SIZE;

    let mut chunker =
        chunker::RollsumChunker::new(crypto::RollsumKey::new().gear_tab(), min_size, max_size);

    let mut buf = vec![0; 1024 * 1024];

    let (pk, _) = crypto::box_keypair();
    let psk = crypto::BoxPreSharedKey::new();
    let mut ectx = crypto::EncryptionContext::new(&pk, &psk);

    let hk = crypto::derive_hash_key(
        &crypto::PartialHashKey::new(),
        &crypto::PartialHashKey::new(),
    );

    let inf = std::io::stdin();
    let mut inf = inf.lock();

    let mut outf = std::io::stdout();
    {
        let mut outf = outf.lock();

        let mut process_data = move |mut data: Vec<u8>| -> Result<(), anyhow::Error> {
            if do_print_chunk_size {
                writeln!(outf, "{}", data.len())?;
            }

            if do_compress {
                data = compression::compress(compression::Scheme::Lz4, data);
            }

            if do_address {
                let address = crypto::keyed_content_address(&data, &hk);
                // use address to ensure compiler can't eliminate it.
                if address.bytes[0] == 0 {
                    data[0] = 0;
                }
            }

            if do_encrypt {
                data = ectx.encrypt_data(data, compression::Scheme::None);
            }

            if do_print {
                outf.write_all(&data)?;
            }

            Ok(())
        };

        loop {
            match inf.read(&mut buf)? {
                0 => break,
                n_read => {
                    if do_chunking {
                        let mut tot_n_chunked: usize = 0;
                        while tot_n_chunked != n_read {
                            let (n_chunked, data) = chunker.add_bytes(&buf[tot_n_chunked..n_read]);
                            tot_n_chunked += n_chunked;

                            if let Some(data) = data {
                                process_data(data)?;
                            }
                        }
                    } else {
                        process_data(buf[0..n_read].to_vec())?;
                    }
                }
            }
        }

        if do_chunking {
            process_data(chunker.finish())?;
        }
    }

    outf.flush()?;

    Ok(())
}

fn serve_main(args: Vec<String>) -> Result<(), anyhow::Error> {
    let mut opts = default_cli_opts();

    opts.optflag(
        "",
        "allow-init",
        "Allow client to initialize the remote repository if it doesn't exist.",
    );
    opts.optflag(
        "",
        "allow-put",
        "Allow client to put more entries into the repository.",
    );
    opts.optflag(
        "",
        "allow-remove",
        "Allow client to remove repository entries.",
    );
    opts.optflag(
        "",
        "allow-gc",
        "Allow client to run the repository garbage collector.",
    );
    opts.optflag(
        "",
        "allow-get",
        "Allow client to get data from the repository.",
    );
    opts.optflag(
        "",
        "allow-list",
        "Allow client to list snapshots and snapshot file lists.",
    );

    let matches = parse_cli_opts(opts, &args[..]);

    if matches.free.len() != 1 {
        die("Expected a single repository path to serve.".to_string());
    }

    let mut allow_init = true;
    let mut allow_put = true;
    let mut allow_remove = true;
    let mut allow_gc = true;
    let mut allow_get = true;
    let mut allow_list = true;

    if matches.opt_present("allow-init")
        || matches.opt_present("allow-put")
        || matches.opt_present("allow-remove")
        || matches.opt_present("allow-gc")
        || matches.opt_present("allow-get")
        || matches.opt_present("allow-list")
    {
        allow_init = matches.opt_present("allow-init");
        allow_put = matches.opt_present("allow-put");
        allow_remove = matches.opt_present("allow-remove");
        allow_gc = matches.opt_present("allow-gc");
        allow_get = matches.opt_present("allow-get");
        // --allow-get and --allow-remove implies --allow-list because they
        // are essentially useless without being able to list items.
        allow_list = allow_get || allow_remove || matches.opt_present("allow-list");
    }

    if atty::is(atty::Stream::Stdout) {
        let _ = writeln!(
            std::io::stderr(),
            "'bupstash serve' running on stdin/stdout..."
        );
    }

    server::serve(
        server::ServerConfig {
            allow_init,
            allow_put,
            allow_remove,
            allow_gc,
            allow_get,
            allow_list,
            repo_path: std::path::Path::new(&matches.free[0]).to_path_buf(),
        },
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
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
        "new-sub-key" => new_sub_key_main(args),
        "list" => list_main(args),
        "list-contents" => list_contents_main(args),
        "diff" => diff_main(args),
        "put" => put_main(args),
        "get" => get_main(args),
        "gc" => gc_main(args),
        "remove" | "rm" => remove_main(args),
        "serve" => serve_main(args),
        "restore-removed" => restore_removed(args),
        "put-benchmark" => put_benchmark(args),
        "version" | "--version" => {
            args[0] = "version".to_string();
            version_main(args)
        }
        "help" | "--help" | "-h" => {
            args[0] = "help".to_string();
            help_main(args);
            Ok(())
        }
        _ => die(format!(
            "Unknown subcommand '{}', try  '{} help'.",
            subcommand, program
        )),
    };

    if let Err(err) = result {
        // Support unix style pipelines, don't print an error on EPIPE.
        match err.root_cause().downcast_ref::<std::io::Error>() {
            Some(io_error) if io_error.kind() == std::io::ErrorKind::BrokenPipe => {
                std::process::exit(1)
            }
            _ => die(format!("bupstash {}: {}", subcommand, err)),
        }
    }
}
