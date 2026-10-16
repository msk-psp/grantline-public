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
        system: String,
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        write: bool,
        #[arg(long)]
        json: bool,
    },
    /// Read-only native ACL checks. Network activity requires --live; no writes or data reads.
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
    /// Run the fictional approval playground. No external services are contacted.
    Demo {
        #[arg(long, default_value_t = 8423)]
        port: u16,
    },
    /// Development-only differential test interface: JSON cases on stdin.
    Parity,
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    match args.command.unwrap_or(Command::Plan {
        source: cli::Source::default(),
        json: false,
        verbose: false,
    }) {
        Command::Plan {
            source,
            json,
            verbose,
        } => cli::plan(&args.config, &source, json, verbose)?,
        Command::Apply {
            live,
            system,
            write,
            expect,
            json,
        } => {
            cli::apply(&args.config, &system, live, write, expect.as_deref(), json)?;
        }
        Command::Restore {
            system,
            backup,
            write,
            json,
        } => {
            cli::restore(&args.config, &system, &backup, write, json)?;
        }
        Command::Probe {
            live,
            observed,
            system,
            subject,
            json,
        } => cli::probe(
            &args.config,
            live,
            observed.as_deref(),
            &system,
            &subject,
            json,
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
