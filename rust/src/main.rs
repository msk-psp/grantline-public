use clap::{Parser, Subcommand};
use grantline_rs::{
    model::{PlanInput, plan},
    web,
};
use std::{
    io::{self, Read},
    net::{Ipv4Addr, SocketAddrV4},
};

#[derive(Parser)]
#[command(about = "Grantline native Rust migration — experimental, local only")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
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
    match Cli::parse().command {
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
