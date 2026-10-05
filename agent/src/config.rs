use anyhow::{Context, Result};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct ProfileConfig {
    pub name: String,
    pub user_id: String,
}

pub fn path() -> Option<PathBuf> {
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("easysign").join("config"))
}

/// Parse profiles from the config file. Keys before any `[section]` form a
/// profile named `default`. Sections without a `user_id` are ignored.
pub fn load() -> Vec<ProfileConfig> {
    let Some(p) = path() else {
        return vec![];
    };
    let Ok(text) = std::fs::read_to_string(&p) else {
        return vec![];
    };

    struct Sec {
        name: String,
        user_id: Option<String>,
    }
    let mut secs: Vec<Sec> = vec![Sec {
        name: "default".into(),
        user_id: None,
    }];

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            secs.push(Sec {
                name: line[1..line.len() - 1].trim().to_string(),
                user_id: None,
            });
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim().trim_matches('"').to_string();
            let sec = secs.last_mut().unwrap();
            if k.trim() == "user_id" {
                sec.user_id = Some(v);
            }
        }
    }

    secs.into_iter()
        .filter_map(|s| {
            s.user_id.map(|u| ProfileConfig {
                name: s.name,
                user_id: u,
            })
        })
        .collect()
}

pub fn save(profiles: &[ProfileConfig]) -> Result<()> {
    let p = path().context("no config path (HOME unset)")?;
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut s = String::from("# easysign accounts (one phone number per section)\n\n");
    for prof in profiles {
        s.push_str(&format!("[{}]\n", prof.name));
        s.push_str(&format!("user_id = {}\n\n", prof.user_id));
    }
    std::fs::write(&p, s)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).ok();
    Ok(())
}
