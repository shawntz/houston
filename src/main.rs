use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "minikta", about = "Minimal self-hosted identity provider")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the database and create an admin user
    Init {
        #[arg(long)]
        admin_username: String,
        #[arg(long)]
        admin_email: String,
    },
    /// Start the server
    Serve {
        #[arg(long, default_value = "config.toml")]
        config: String,
    },
    /// Regenerate signing keys
    GenerateKeys,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { admin_username, admin_email } => {
            println!("Initializing minikta with admin user: {admin_username} <{admin_email}>");
            todo!("init command")
        }
        Commands::Serve { config } => {
            println!("Starting minikta with config: {config}");
            todo!("serve command")
        }
        Commands::GenerateKeys => {
            println!("Regenerating signing keys...");
            todo!("generate-keys command")
        }
    }
}
