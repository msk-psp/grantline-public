use clap::{Parser, Subcommand};
use grantline_rs::{
    cli,
    model::{PlanInput, plan},
    web,
};
use std::{
    io::{self, Read},
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
};

#[derive(Parser)]
#[command(about = "Grantline native Rust migration — experimental, dry-run by default")]
struct Cli {
    #[arg(short = 'c', long, global = true, default_value = "grantline.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    /// Record a fresh observation and preview drift notifications; external delivery requires --send.
    Notify {
        #[arg(long)]
        live: bool,
        #[arg(long)]
        send: bool,
        #[arg(long)]
        json: bool,
    },
    /// Print a read-only plan; native PostgreSQL/ClickHouse/S3 observation requires --live.
    Plan {
        #[command(flatten)]
        source: cli::Source,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        verbose: bool,
    },
    /// Preview local S3 IAM or (--live) PostgreSQL/ClickHouse ACLs; --write requires a reviewed plan.
    Apply {
        #[arg(long)]
        database: Option<String>,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        live: bool,
        #[arg(long)]
        system: String,
        #[arg(long)]
        write: bool,
        #[arg(long, requires = "write")]
        expect: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Restore a private original-byte backup only if the target still matches its applied state.
    Restore {
        #[arg(long)]
        live: bool,
        #[arg(long)]
        system: String,
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        write: bool,
        #[arg(long)]
        json: bool,
    },
    /// Native ACL checks. Network requires --live; S3 temporary-object writes also require --write.
    Probe {
        #[arg(long)]
        live: bool,
        /// Use a saved baseline while probing the current server; may be combined with --live.
        #[arg(long)]
        observed: Option<PathBuf>,
        #[arg(long)]
        system: Vec<String>,
        #[arg(long)]
        subject: Vec<String>,
        /// S3 Write only: create a unique probe object and attempt cleanup with the same identity.
        #[arg(long, requires = "live")]
        write: bool,
        #[arg(long)]
        json: bool,
    },
    /// Explicitly save a private JSONL snapshot; never applies IAM.
    Snapshot {
        #[command(flatten)]
        source: cli::Source,
        #[arg(long)]
        directory: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// List snapshots or compare --from/--to or --since.
    History {
        #[arg(long, conflicts_with = "since")]
        from: Option<PathBuf>,
        #[arg(long, requires = "from")]
        to: Option<PathBuf>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Inspect authorization paths, including role hops and declared bridges.
    Graph {
        #[command(flatten)]
        source: cli::Source,
        #[arg(long)]
        subject: Vec<String>,
        #[arg(long)]
        resource: Vec<String>,
        #[arg(long)]
        depth: Vec<String>,
        #[arg(long, default_value_t = 1000)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Run the native console. Local preview is read-only; live services require --live.
    Serve {
        #[arg(long, default_value = "127.0.0.1")]
        host: std::net::IpAddr,
        #[arg(long, default_value_t = 8424)]
        port: u16,
        #[arg(long)]
        live: bool,
        /// Explicitly expose a read-only fixture preview on a non-loopback listener.
        #[arg(long)]
        public_preview: bool,
    },
    /// Copy offline approval history into a new private versioned store (dry-run by default).
    #[cfg(unix)]
    Migrate {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        destination: PathBuf,
        #[arg(long)]
        write: bool,
        /// Confirm all writers using the source store have been stopped.
        #[arg(long, requires = "write")]
        offline: bool,
    },
    /// Run the fictional approval playground. No external services are contacted.
    Demo {
        #[arg(long, default_value_t = 8423)]
        port: u16,
    },
    /// Development-only differential test interface: JSON cases on stdin.
    Parity,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    let needs_env = match args.command.as_ref() {
        Some(
            Command::Plan { source, .. }
            | Command::Snapshot { source, .. }
            | Command::Graph { source, .. },
        ) => source.live,
        Some(
            Command::Apply { live, .. }
            | Command::Restore { live, .. }
            | Command::Probe { live, .. },
        ) => *live,
        Some(Command::Notify { live, send, .. }) => *live || *send,
        Some(Command::Serve { .. }) => true,
        _ => false,
    };
    if needs_env {
        for (key, value) in grantline_rs::config::env_file(&args.config)? {
            // Single-threaded startup, before the Tokio runtime exists.
            unsafe {
                std::env::set_var(key, value);
            }
        }
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(args))
}
async fn run(args: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match args.command.unwrap_or(Command::Plan {
        source: cli::Source::default(),
        json: false,
        verbose: false,
    }) {
        Command::Notify { live, send, json } => {
            grantline_rs::notify::run(&args.config, live, send, json)?
        }
        Command::Plan {
            source,
            json,
            verbose,
        } => cli::plan(&args.config, &source, json, verbose)?,
        Command::Apply {
            database,
            subject,
            live,
            system,
            write,
            expect,
            json,
        } => {
            cli::apply(
                &args.config,
                &system,
                live,
                write,
                expect.as_deref(),
                json,
                database.as_deref(),
                subject.as_deref(),
            )?;
        }
        Command::Restore {
            live,
            system,
            backup,
            write,
            json,
        } => {
            #[cfg(unix)]
            if live {
                let r = grantline_rs::s3::remote_writer::restore(
                    &args.config,
                    &system,
                    &backup,
                    write,
                )?;
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                cli::restore(&args.config, &system, &backup, write, json)?;
            }
            #[cfg(not(unix))]
            cli::restore(&args.config, &system, &backup, write, json)?;
        }
        Command::Probe {
            live,
            observed,
            system,
            subject,
            write,
            json,
        } => cli::probe(
            &args.config,
            live,
            observed.as_deref(),
            &system,
            &subject,
            json,
            write,
        )?,
        Command::Snapshot {
            source,
            directory,
            json,
        } => cli::record(&args.config, &source, directory, json)?,
        Command::History {
            from,
            to,
            since,
            json,
        } => cli::history(
            &args.config,
            from.as_deref(),
            to.as_deref(),
            since.as_deref(),
            json,
        )?,
        Command::Graph {
            source,
            subject,
            resource,
            depth,
            limit,
            json,
        } => cli::graph(
            &args.config,
            &source,
            &subject,
            &resource,
            &depth,
            limit,
            json,
        )?,
        Command::Serve {
            host,
            port,
            live,
            public_preview,
        } => grantline_rs::console::serve(args.config, host, port, live, public_preview).await?,
        #[cfg(unix)]
        Command::Migrate {
            source,
            destination,
            write,
            offline,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&grantline_rs::migration::migrate(
                    &source,
                    &destination,
                    write,
                    offline
                )?)?
            );
        }
        Command::Demo { port } => {
            let listener =
                tokio::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).await?;
            let port = listener.local_addr()?.port();
            println!("Grantline Rust + Leptos playground: http://127.0.0.1:{port}/demo");
            println!(
                "Fictional identities, in-memory state, simulated Slack and PRs. Ctrl-C to stop."
            );
            axum::serve(listener, web::app(port))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
        Command::Parity => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input)?;
            let cases: Vec<PlanInput> = serde_json::from_str(&input)?;
            println!(
                "{}",
                serde_json::to_string(&cases.into_iter().map(plan).collect::<Vec<_>>())?
            );
        }
    }
    Ok(())
}
