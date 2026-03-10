use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "houston", about = "Minimal self-hosted identity provider")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the database and create an admin user
    Init {
        #[arg(long, default_value = "config.toml")]
        config: String,
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
    GenerateKeys {
        #[arg(long, default_value = "config.toml")]
        config: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { config: config_path, admin_username, admin_email } => {
            let cfg = houston::config::AppConfig::load(&config_path)?;

            println!("Initializing houston database at {}", cfg.database.path);
            let conn = houston::db::initialize(&cfg.database.path)?;

            // Check if admin already exists
            if let Ok(Some(_)) = houston::db::users::get_user_by_username(&conn, &admin_username) {
                println!("Admin user '{}' already exists, skipping creation.", admin_username);
                return Ok(());
            }

            // Prompt for password
            let password = rpassword::prompt_password("Admin password: ")?;
            let password_confirm = rpassword::prompt_password("Confirm password: ")?;

            if password != password_confirm {
                anyhow::bail!("Passwords do not match");
            }

            if password.len() < cfg.password.min_length as usize {
                anyhow::bail!("Password must be at least {} characters", cfg.password.min_length);
            }

            let password_hash = houston::auth::password::hash_password(&password)?;

            let user = houston::db::users::create_user(&conn, &houston::db::users::CreateUser {
                username: admin_username.clone(),
                email: admin_email.clone(),
                display_name: admin_username.clone(),
                password_hash,
                is_admin: true,
            })?;

            println!("Created admin user '{}' (id: {})", user.username, user.id);
            println!("You can now start houston with: houston serve");
            Ok(())
        }
        Commands::Serve { config: config_path } => {
            let cfg = houston::config::AppConfig::load(&config_path)?;
            houston::server::run(cfg).await?;
            Ok(())
        }
        Commands::GenerateKeys { config: config_path } => {
            let cfg = houston::config::AppConfig::load(&config_path)?;
            println!("Regenerating signing keys...");

            let keys_dir = "keys";
            std::fs::create_dir_all(keys_dir)?;

            // Generate Ed25519
            let ed25519_key_path = format!("{keys_dir}/ed25519.key.enc");
            let kp = houston::crypto::keys::generate_ed25519_keypair()?;
            houston::crypto::keys::save_encrypted_key(
                &kp.private_key_pkcs8,
                &ed25519_key_path,
                &cfg.secrets.master_secret,
            )?;
            std::fs::write(format!("{keys_dir}/ed25519.kid"), &kp.kid)?;
            println!("Generated Ed25519 signing key (kid: {})", kp.kid);

            println!("Keys saved to {keys_dir}/");
            Ok(())
        }
    }
}
