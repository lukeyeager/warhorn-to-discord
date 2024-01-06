use clap::Parser;

// =============================================================================
// Command-line args
// =============================================================================

#[derive(clap::Parser, Debug)]
struct Args {
    /// Path to the JSON config file
    #[arg(short, long, default_value = "config.json")]
    config: std::path::PathBuf,

    /// sqlite3 database
    #[arg(short, long, default_value = "data.db")]
    database: std::path::PathBuf,
}

// =============================================================================
// Config file
// =============================================================================

#[derive(serde::Deserialize)]
struct ConfigTarget {
    discord_hook: String,
    events: Vec<String>,
}

#[derive(serde::Deserialize)]
struct Config {
    warhorn_token: String,
    targets: Vec<ConfigTarget>,
}

fn read_config(path: std::path::PathBuf) -> Config {
    let file = std::fs::File::open(path).expect("open config file");
    let reader = std::io::BufReader::new(file);
    serde_json::from_reader(reader).expect("parse config file")
}

// =============================================================================
// Database
// =============================================================================

fn open_db(path: &std::path::PathBuf) -> (rusqlite::Connection, bool) {
    let flags =
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    match rusqlite::Connection::open_with_flags(path, flags) {
        Ok(conn) => (conn, false),
        Err(..) => {
            let conn = rusqlite::Connection::open_with_flags(
                path,
                flags | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
            )
            .expect("open db");
            conn.execute(
                "CREATE TABLE IF NOT EXISTS sessions (
                    event_slug TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    PRIMARY KEY (event_slug, session_id)
                )",
                (),
            )
            .expect("CREATE TABLE");
            (conn, true)
        }
    }
}

fn select_from_db<'a>(conn: &rusqlite::Connection, event_slug: &'a str) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT session_id FROM sessions WHERE event_slug = ?")
        .expect("prepare SELECT");
    let mut session_ids = Vec::new();
    for session_id in stmt
        .query_map([event_slug], |row| row.get(0))
        .expect("SELECT")
    {
        session_ids.push(session_id.expect("read row from SELECT"));
    }
    session_ids
}

fn insert_into_db<'a>(conn: &rusqlite::Connection, event_slug: &'a str, session_ids: Vec<&'a str>) {
    let mut stmt = conn
        .prepare("INSERT INTO sessions VALUES (?1, ?2)")
        .expect("prepare INSERT");
    for session_id in session_ids.iter() {
        stmt.execute([event_slug, session_id])
            .expect("execute INSERT");
    }
}

fn delete_from_db<'a>(conn: &rusqlite::Connection, event_slug: &'a str, session_ids: Vec<&'a str>) {
    let mut stmt = conn
        .prepare("DELETE FROM sessions WHERE event_slug=$1 AND session_id=$2")
        .expect("prepare DELETE");
    for session_id in session_ids.iter() {
        stmt.execute([event_slug, session_id])
            .expect("execute DELETE");
    }
}

// =============================================================================
// HTTP utils
// =============================================================================

fn send_request_with_backoff(
    req: reqwest::blocking::RequestBuilder,
    respect_retry_after: bool,
) -> Result<reqwest::blocking::Response, backoff::Error<reqwest::Error>> {
    let op = || {
        let resp = req
            .try_clone()
            .unwrap()
            .send()
            .map_err(backoff::Error::Permanent)?;

        if resp.status() == 429 {
            if respect_retry_after {
                if let Some(secs_value) = resp.headers().get("Retry-After") {
                    if let Ok(secs_str) = secs_value.to_str() {
                        if let Ok(secs) = secs_str.parse::<f64>() {
                            println!(
                                "Respecting Retry-After header, waiting {} seconds ...",
                                secs_str
                            );
                            let duration = std::time::Duration::from_secs_f64(secs);
                            let err_option = match resp.error_for_status_ref() {
                                Ok(_) => None,
                                Err(e) => Some(e),
                            };
                            return Err(backoff::Error::retry_after(err_option.unwrap(), duration));
                        }
                    }
                }
            }
            // TODO: figure out how to explicitly convert the error properly
            // for now, the '?' operator works
            resp.error_for_status()?;
            panic!("should never get here");
        }
        resp.error_for_status().map_err(backoff::Error::Permanent)
    };
    backoff::retry(backoff::ExponentialBackoff::default(), op)
}

// =============================================================================
// Warhorn API
// =============================================================================

#[derive(Debug)]
struct Session {
    id: String,
    signup_url: String,
}

fn get_event_sessions<'a>(event_slug: &'a str, warhorn_token: &'a str) -> Vec<Session> {
    let now_st = std::time::SystemTime::now();
    let now_dt: chrono::prelude::DateTime<chrono::prelude::Utc> = now_st.clone().into();
    let now_str = format!("{}", now_dt.format("%+"));

    let body = serde_json::json!({
        "query": "query($event: String!, $startsAfter: ISO8601DateTime!) {eventSessions(events: [$event], startsAfter: $startsAfter){nodes{id signupUrl}}}",
        "variables": {
            "event": event_slug,
            "startsAfter": now_str,
        },
    });
    let req = reqwest::blocking::Client::new()
        .post("https://warhorn.net/graphql")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", warhorn_token))
        .body(body.to_string());
    let resp = send_request_with_backoff(req, true).expect("POST to warhorn");
    if resp.status() != 200 {
        panic!("warhorn POST returned {}", resp.status());
    }
    let value: serde_json::Value = resp.json().expect("parse JSON");
    let mut sessions = Vec::new();
    for session in value["data"]["eventSessions"]["nodes"]
        .as_array()
        .unwrap()
        .iter()
    {
        let session = Session {
            id: session["id"].as_str().unwrap().to_string(),
            signup_url: session["signupUrl"].as_str().unwrap().to_string(),
        };
        sessions.push(session);
    }
    sessions
}

// =============================================================================
// Discord API
// =============================================================================

fn send_message<'a>(discord_hook: &'a str, session: &'a Session) {
    let req = reqwest::blocking::Client::new()
        .post(discord_hook)
        .header("Content-Type", "application/json")
        .body(serde_json::json!({"content": session.signup_url}).to_string());

    // Discord's rate-limiting doesn't seem to work quite right. They send very large Retry-After
    // values. Larger than seems to be actually necesssary. So we'll just use the default
    // exponential backoff instead.

    send_request_with_backoff(req, false).expect("POST to discord");
}

// =============================================================================
// main
// =============================================================================

fn main() {
    let args = Args::parse();
    let config = read_config(args.config);
    let (db, db_is_new) = open_db(&args.database);

    for target in config.targets.iter() {
        for event_slug in target.events.iter() {
            println!("\t{}", event_slug);
            let sessions = get_event_sessions(event_slug, &config.warhorn_token);

            let previous_session_ids = select_from_db(&db, event_slug);

            let mut new_session_ids = Vec::new();
            for session in sessions.iter() {
                let mut found = false;
                for s in &previous_session_ids {
                    if s == &session.id {
                        found = true;
                        break;
                    }
                }
                if found {
                    println!("{} OLD", session.id);
                } else {
                    println!("{} NEW", session.id);
                    new_session_ids.push(session.id.as_str());
                    if !db_is_new {
                        send_message(&target.discord_hook, session);
                    }
                }
            }

            let mut old_session_ids = Vec::new();
            for session_id in previous_session_ids.iter() {
                let mut found = false;
                for s in sessions.iter() {
                    if &s.id == session_id {
                        found = true;
                        break;
                    }
                }
                if !found {
                    println!("{} SHOULD DELETE", session_id);
                    old_session_ids.push(session_id.as_str());
                }
            }

            insert_into_db(&db, event_slug, new_session_ids);
            delete_from_db(&db, event_slug, old_session_ids);
        }
    }
}
