use std::collections::HashMap;
use serde::de::DeserializeOwned;

use crate::synology_api::responses::{SynologyResult, LoginResult, GetSharesResult};

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

    pub fn get_shares(&self) -> Result<GetSharesResult, i32> {
        let mut additional = HashMap::new();
        additional.insert("additional", "%5B%22volume_status%22%2C%22time%22%5D");
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
                            let parsed_result = res.json::<SynologyResult<T>>();

                            match parsed_result {
                                Ok(res) => {
                                    if !res.success {
                                        Err(-1)
                                    } else {
                                        Ok(res.data)
                                    }
                                },
                                Err(_error) => {
                                    println!("err: {}", _error);
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