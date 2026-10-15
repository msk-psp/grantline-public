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
#[command(about = "Grantline native Rust migration — experimental, local only")]
struct Cli {
    #[arg(short = 'c', long, global = true, default_value = "grantline.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    /// Read local fixtures or a saved observation and print a read-only plan.
    Plan {
        #[arg(long)]
        observed: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        verbose: bool,
    },
    /// Explicitly save a private JSONL snapshot; never applies IAM.
    Snapshot {
        #[arg(long)]
        observed: Option<PathBuf>,
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
        #[arg(long)]
        observed: Option<PathBuf>,
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
        observed: None,
        json: false,
        verbose: false,
    }) {
        Command::Plan {
            observed,
            json,
            verbose,
        } => cli::plan(&args.config, observed.as_deref(), json, verbose)?,
        Command::Snapshot {
            observed,
            directory,
            json,
        } => cli::record(&args.config, observed.as_deref(), directory, json)?,
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
            observed,
            subject,
            resource,
            depth,
            limit,
            json,
        } => cli::graph(
            &args.config,
            observed.as_deref(),
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
