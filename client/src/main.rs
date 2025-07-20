use mime_guess::MimeGuess;
use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};
use std::{env, fs, path::PathBuf};

const GLOBAL_HELP: &str = r#"
Available commands:
  config          Configure token and server URL
  create          Create a new paste
  get             Get a paste by ID or alias
  delete          Delete a paste by ID
  list            List all pastes
  list-tokens     List all tokens
  create-token    Create a new token
  delete-token    Delete a token
  set-admin-key   Set admin status for a token
  help            Show this help message or command-specific help
"#;

const CONFIG_HELP: &str = r#"
config [--token <token>] [--server-url <url>]
  Set or update config values (token and server URL).
"#;

const CREATE_HELP: &str = r#"
create [--aliases <aliases>] [--header <key:value>] [file|-]
  Create a new paste from a file or stdin.
"#;

const GET_HELP: &str = r#"
get <id|alias>
  Retrieve a paste by ID or alias.
"#;

const DELETE_HELP: &str = r#"
delete <paste_id>
  Delete a paste by its ID.
"#;

const LIST_HELP: &str = r#"
list
  List all pastes.
"#;

const LIST_TOKENS_HELP: &str = r#"
list-tokens
  List all tokens.
"#;

const CREATE_TOKEN_HELP: &str = r#"
create-token
  Create a new token (admin only).
"#;

const DELETE_TOKEN_HELP: &str = r#"
delete-token <token>
  Delete a token (admin only).
"#;

const SET_ADMIN_KEY_HELP: &str = r#"
set-admin-key <target-token> <true|false>
  Set admin status for the target token.
"#;

#[derive(Serialize, Deserialize, Debug, Default)]
struct Config {
    token: Option<String>,
    server_url: Option<String>,
}

impl Config {
    fn path() -> PathBuf {
        let mut config_dir = dirs::config_dir().expect("Cannot find config dir");
        config_dir.push("kybes-pastes");
        fs::create_dir_all(&config_dir).unwrap();
        config_dir.push("config.toml");
        config_dir
    }

    fn load() -> Self {
        let path = Self::path();
        if path.exists() {
            let content = fs::read_to_string(path).expect("Failed to read config");
            toml::from_str(&content).expect("Invalid config format")
        } else {
            Self::default()
        }
    }

    fn save(&self) {
        let content = toml::to_string_pretty(self).expect("Failed to serialize config");
        fs::write(Self::path(), content).expect("Failed to write config");
    }
}

fn parse_header(s: &str) -> Result<(String, String), String> {
    let parts: Vec<_> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(format!("Header must be in key:value format, got '{}'", s));
    }
    Ok((parts[0].trim().to_string(), parts[1].trim().to_string()))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| {
        eprintln!("No command given");
        std::process::exit(1);
    });

    let mut config = Config::load();

    match command.as_str() {
        "config" => {
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--token" => config.token = args.next(),
                    "--server-url" => config.server_url = args.next(),
                    _ => {}
                }
            }
            config.save();
            println!("Config saved");
        }

        "create" => {
            let mut aliases = None;
            let mut file = None;
            let mut headers = vec![];

            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--aliases" => aliases = args.next(),
                    "--header" => {
                        if let Some(val) = args.next() {
                            headers.push(parse_header(&val).unwrap_or_else(|e| {
                                eprintln!("Error parsing header: {}", e);
                                std::process::exit(1);
                            }));
                        }
                    }
                    _ if file.is_none() => file = Some(arg),
                    _ => {}
                }
            }

            let (content, maybe_filename) = match file.as_deref() {
                Some("-") | None => {
                    use tokio::io::{self, AsyncReadExt};
                    let mut buf = Vec::new();
                    io::stdin().read_to_end(&mut buf).await?;
                    (buf, None)
                }
                Some(path) => {
                    let data = fs::read(path)?;
                    (data, Some(path))
                }
            };

            let server_url = config.server_url.as_ref().expect("Missing server_url");
            let token = config.token.as_ref().expect("Missing token");

            let mime = maybe_filename
                .map(MimeGuess::from_path)
                .and_then(|g| g.first_raw())
                .unwrap_or("application/octet-stream");

            let client = reqwest::Client::new();
            let mut req = client
                .post(format!("{}/api/create_paste", server_url))
                .header(AUTHORIZATION, format!("Bearer {}", token))
                .header("X-Paste-Content-Type", mime);

            if let Some(a) = aliases {
                req = req.header("X-Aliases", a);
            }

            for (k, v) in headers {
                req = req.header(format!("X-Paste-{}", k), v);
            }

            let resp = req.body(content).send().await?;
            if resp.status().is_success() {
                let id: String = resp.json().await?;
                println!("Created paste with ID: {}", id);
            } else {
                eprintln!("Failed: {:?}", resp.text().await?);
            }
        }

        "get" => {
            let id_or_alias = args.next().expect("Missing ID or alias");
            let server_url = config.server_url.as_ref().expect("Missing server_url");
            let token = config.token.as_ref().expect("Missing token");

            let client = reqwest::Client::new();
            let resp = client
                .post(format!("{}/api/get_paste/{}", server_url, id_or_alias))
                .header(AUTHORIZATION, token)
                .json(&serde_json::json!({ "token": token }))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                eprintln!("Failed: {:?}", resp.text().await?);
            }
        }

        "delete" => {
            let paste_id = args.next().expect("Missing paste ID");
            let server_url = config.server_url.as_ref().expect("Missing server_url");
            let token = config.token.as_ref().expect("Missing token");

            let resp = reqwest::Client::new()
                .post(format!("{}/api/delete_paste", server_url))
                .header(AUTHORIZATION, token)
                .json(&serde_json::json!({ "token": token, "paste_id": paste_id }))
                .send()
                .await?;

            println!("{}", resp.text().await?);
        }

        "list" => {
            let server_url = config.server_url.as_ref().expect("Missing server_url");
            let token = config.token.as_ref().expect("Missing token");

            let resp = reqwest::Client::new()
                .post(format!("{}/api/get_pastes", server_url))
                .header(AUTHORIZATION, token)
                .json(&serde_json::json!({ "token": token }))
                .send()
                .await?;

            if resp.status().is_success() {
                let pastes: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&pastes)?);
            } else {
                eprintln!("Failed: {:?}", resp.text().await?);
            }
        }

        "list-tokens" => {
            let server_url = config.server_url.as_ref().expect("Missing server_url");
            let token = config.token.as_ref().expect("Missing token");

            let resp = reqwest::Client::new()
                .post(format!("{}/api/get_tokens", server_url))
                .header(AUTHORIZATION, format!("Bearer {}", token))
                .json(&serde_json::json!({ "token": token }))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                eprintln!("Failed: {:?}", resp.text().await?);
            }
        }

        "create-token" => {
            let server_url = config.server_url.as_ref().expect("Missing server_url");
            let token = config.token.as_ref().expect("Missing token");

            let resp = reqwest::Client::new()
                .post(format!("{}/api/create_token", server_url))
                .header(AUTHORIZATION, format!("Bearer {}", token))
                .json(&serde_json::json!({ "admin_token": token }))
                .send()
                .await?;

            if resp.status().is_success() {
                let val: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&val)?);
            } else {
                eprintln!("Failed: {:?}", resp.text().await?);
            }
        }

        "delete-token" => {
            let token_to_delete = args.next().expect("Missing token to delete");
            let server_url = config.server_url.as_ref().expect("Missing server_url");
            let token = config.token.as_ref().expect("Missing token");

            let resp = reqwest::Client::new()
                .post(format!("{}/api/delete_token", server_url))
                .header(AUTHORIZATION, format!("Bearer {}", token))
                .json(&serde_json::json!({
                    "admin_token": token,
                    "token_to_delete": token_to_delete
                }))
                .send()
                .await?;

            println!("{}", resp.text().await?);
        }

        "set-admin-key" => {
            let target_token = args.next().expect("Missing target-token");
            let is_admin_str = args.next().expect("Missing true|false");

            let is_admin = match is_admin_str.as_str() {
                "true" => true,
                "false" => false,
                _ => {
                    eprintln!("Expected 'true' or 'false'");
                    std::process::exit(1);
                }
            };

            let admin_token = config.token.clone().expect("Missing token in config");
            let server_url = config
                .server_url
                .clone()
                .expect("Missing server_url in config");

            let body = serde_json::json!({
                "admin_token": admin_token,
                "target_token": target_token,
                "is_admin": is_admin
            });

            let client = reqwest::Client::new();
            let res = client
                .post(&format!("{}/api/set_admin", server_url))
                .header(AUTHORIZATION, format!("Bearer {}", admin_token))
                .json(&body)
                .send()
                .await?
                .text()
                .await?;

            println!("{res}");
        }

        "help" => {
            if let Some(cmd) = args.next() {
                match cmd.as_str() {
                    "config" => println!("{CONFIG_HELP}"),
                    "create" => println!("{CREATE_HELP}"),
                    "get" => println!("{GET_HELP}"),
                    "delete" => println!("{DELETE_HELP}"),
                    "list" => println!("{LIST_HELP}"),
                    "list-tokens" => println!("{LIST_TOKENS_HELP}"),
                    "create-token" => println!("{CREATE_TOKEN_HELP}"),
                    "delete-token" => println!("{DELETE_TOKEN_HELP}"),
                    "set-admin-key" => println!("{SET_ADMIN_KEY_HELP}"),
                    _ => {
                        eprintln!("Unknown command '{}'. Use `help` to see all commands.", cmd);
                        std::process::exit(1);
                    }
                }
            } else {
                println!("{GLOBAL_HELP}");
            }
        }

        _ => {
            eprintln!("Unknown command");
            std::process::exit(1);
        }
    }

    Ok(())
}
