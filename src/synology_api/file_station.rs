use std::collections::HashMap;
use serde::de::DeserializeOwned;
use urlencoding::encode;

use crate::synology_api::responses::{SynologyResult, LoginResult, ListSharesResult, ListFilesResult};

pub struct FileStation {
    pub hostname: String,
    base_url: String,
    sid: Option<String>,
    version: u8
}

impl FileStation {
    pub fn new(hostname: String, port: u16, secured: bool, version: u8) -> Self {
        let protocol = if secured { "https" } else { "http" };
        let base_url = format!("{}://{}:{}", protocol, hostname, port);

        FileStation { hostname, base_url: base_url.to_string(), version, sid: Default::default() }
    }

    pub fn get_info_for_path(&self, path: &str) -> Result<ListFilesResult, i32> {
        self.get_info_for_paths(vec!(path))
    }

    pub fn get_info_for_paths(&self, paths: Vec<&str>) -> Result<ListFilesResult, i32> {
        let mut paths_str = "".to_string();
        paths_str += paths.first().unwrap();

        if paths_str.len() > 1 {
            for file in paths.iter().skip(1) {
                paths_str += format!(",{}", file).as_ref();
            }
        }

        let mut additional = HashMap::new();

        let encoded_path = encode(paths_str.as_str()).to_string();
        additional.insert("path", encoded_path.as_str());
        
        let encoded_additional = encode("[\"size\",\"time\"]").to_string();
        additional.insert("additional", encoded_additional.as_str());

        self.get("SYNO.FileStation.List", 2, "getinfo", &additional)
    }

    pub fn list_files(&self, path: &str) -> Result<ListFilesResult, i32> {
        let mut additional = HashMap::new();

        let encoded_path = encode(path).to_string();
        additional.insert("folder_path", encoded_path.as_str());

        
        let encoded_additional = encode("[\"size\",\"time\"]").to_string();
        additional.insert("additional", encoded_additional.as_str());

        self.get("SYNO.FileStation.List", 2, "list", &additional)
    }

    pub fn list_shares(&self) -> Result<ListSharesResult, i32> {
        let mut additional = HashMap::new();

        let encoded_additional = encode("[\"volume_status\",\"time\"]").to_string();
        additional.insert("additional", encoded_additional.as_str());

        self.get("SYNO.FileStation.List", 2, "list_share", &additional)
    }

    pub fn login(&mut self, username: &str, password: &str) -> Result<(), i32> {
        let login_url = format!(
            "{}/webapi/auth.cgi?api=SYNO.API.Auth&version={}&method=login&account={}&passwd={}&session=FileStation&format=sid",
            self.base_url,
            self.version,
            username,
            password);
        let result = reqwest::blocking::get(login_url);

        match result {
            Ok(res) => {
                if res.status() == 200 {
                    let login_result = res.json::<SynologyResult<LoginResult>>().unwrap();
                    
                    if login_result.success {
                        self.sid = Some(login_result.data.sid);
                        Ok(())
                    }
                    else {
                        Err(-1)
                    }
                }
                else {
                    Err(res.status().as_u16() as i32)
                }
            },
            Err(_error) => Err(-1)
        }
    }

    pub fn logout(&self) -> Result<(), i32> {
        let mut additional = HashMap::new();
        additional.insert("session", "FileStation");

        self.get("SYN.API.Auth", 1, "logout", &additional)
    }

    fn get<T: DeserializeOwned>(&self, api: &str, version: u8, method: &str, additional: &HashMap<&str, &str>) -> Result<T, i32> {
        match &self.sid {
            Some(sid) => {
                let mut url = format!(
                    "{}/webapi/entry.cgi?api={}&version={}&method={}&_sid={}",
                    self.base_url,
                    api,
                    version,
                    method,
                    sid
                );

                println!("url: {}", url);

                for (key, value) in &*additional {
                    url += format!("&{}={}", key, value).as_ref();
                }

                println!("url = {}", url);

                let result = reqwest::blocking::get(url);

                match result {
                    Ok(res) => {
                        if res.status() == 200 {
                            let text_result = res.text();

                            match text_result {
                                Ok(text) => {
                                    let parsed_result = serde_json::from_str::<SynologyResult<T>>(text.as_str());

                                    match parsed_result {
                                        Ok(parsed) => {
                                            if !parsed.success {
                                                Err(-1)
                                            } else {
                                                Ok(parsed.data)
                                            }
                                        },
                                        Err(error) => {
                                            println!("err: {} with json '{}'.", error, text);
                                            Err(-1)
                                        }
                                    }
                                },
                                Err(error) => {
                                    println!("err: {}", error);
                                    Err(-1)
                                }
                            }
                        }
                        else {
                            Err(res.status().as_u16() as i32)
                        }
                    },
                    Err(_error) => Err(-1)
                }
            },
            None => Err(403)
        }
    }
}