use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("transport: {0}")]
    Transport(String),

    #[error("api {code}: {description}")]
    Api { code: String, description: String },

    #[error("unexpected response: {0}")]
    Unexpected(String),

    #[error("not authenticated")]
    NotAuthenticated,

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<ureq::Error> for Error {
    fn from(e: ureq::Error) -> Self {
        match e {
            ureq::Error::Status(code, resp) => {
                let body = resp.into_string().unwrap_or_default();
                match serde_json::from_str::<serde_json::Value>(&body) {
                    Ok(v) => {
                        let desc = v
                            .get("error_description")
                            .or_else(|| v.get("error"))
                            .and_then(|x| x.as_str())
                            .unwrap_or(&body)
                            .to_string();
                        Error::Api {
                            code: code.to_string(),
                            description: desc,
                        }
                    }
                    Err(_) => Error::Api {
                        code: code.to_string(),
                        description: body,
                    },
                }
            }
            ureq::Error::Transport(t) => Error::Transport(t.to_string()),
        }
    }
}
