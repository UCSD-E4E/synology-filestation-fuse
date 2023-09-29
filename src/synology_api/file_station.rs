use std::{collections::HashMap, sync::Mutex, time::{Duration, SystemTime}};
use serde::de::DeserializeOwned;
use urlencoding::encode;
use log::{debug, error};

use crate::synology_api::responses::{SynologyResult, LoginResult, ListSharesResult, ListFilesResult};

use super::responses::{FileStationItem, FileAdditional};


struct FileStationCacheItem {
    cache_time: SystemTime,
    data: serde_json::Value
}

pub struct FileStation {
    pub hostname: String,
    pub base_url: String,

    cache: Mutex<HashMap<String, FileStationCacheItem>>,
    cache_lifetime: Duration,
    sid: Option<String>,
}

impl FileStation {
    pub fn new(hostname: &str, port: u16, secured: bool, cache_lifetime: Duration) -> Self {
        let protocol = if secured { "https" } else { "http" };
        let base_url = format!("{}://{}:{}", protocol, hostname, port);

        FileStation {
            hostname: hostname.to_string(),
            base_url: base_url.to_string(),
            cache: Mutex::new(HashMap::new()),
            cache_lifetime,
            sid: Default::default()
        }
    }

    pub fn get_info_for_path(&self, path: &str) -> Result<FileStationItem<FileAdditional>, i32> {
        match self.get_info_for_paths(vec!(path)) {
            Ok(result) => Ok(result.files.first().unwrap().clone()),
            Err(error) => Err(error)
        }
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
        
        let encoded_additional = encode("[\"size\",\"time\",\"perm\"]").to_string();
        additional.insert("additional", encoded_additional.as_str());

        let result: Result<serde_json::Value, i32> = self.get("SYNO.FileStation.List", 2, "getinfo", &additional, true);
        match result {
            Ok(value) => {
                for item in value["files"].as_array().unwrap().iter() {
                    if item["code"].is_number() {
                        return Err(item["code"].as_i64().unwrap() as i32);
                    }
                }

                let value_str = value.to_string();
                let parsed_result = serde_json::from_value::<ListFilesResult>(value);

                return match parsed_result {
                    Ok(parsed) => Ok(parsed),
                    Err(error) => {
                        error!("Error: {} with json: {}", error, value_str);

                        Err(-4)
                    }
                }
            },
            Err(error) => Err(error)
        }
    }

    pub fn list_files(&self, path: &str) -> Result<ListFilesResult, i32> {
        let mut additional = HashMap::new();

        let encoded_path = encode(path).to_string();
        additional.insert("folder_path", encoded_path.as_str());

        
        let encoded_additional = encode("[\"size\",\"time\",\"perm\"]").to_string();
        additional.insert("additional", encoded_additional.as_str());

        self.get("SYNO.FileStation.List", 2, "list", &additional, true)
    }

    pub fn list_shares(&self) -> Result<ListSharesResult, i32> {
        let mut additional = HashMap::new();

        let encoded_additional = encode("[\"volume_status\",\"time\",\"perm\"]").to_string();
        additional.insert("additional", encoded_additional.as_str());

        self.get("SYNO.FileStation.List", 2, "list_share", &additional, true)
    }

    pub fn login(&mut self, username: &str, password: &str) -> Result<(), i32> {
        let login_url = format!(
            "{}/webapi/auth.cgi?api=SYNO.API.Auth&version={}&method=login&account={}&passwd={}&session=FileStation&format=sid",
            self.base_url,
            3,
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
                        Err(-5)
                    }
                }
                else {
                    Err(res.status().as_u16() as i32)
                }
            },
            Err(_error) => Err(-6)
        }
    }

    pub fn logout(&self) -> Result<(), i32> {
        let mut additional = HashMap::new();
        additional.insert("session", "FileStation");

        let result = self.get("SYN.API.Auth", 1, "logout", &additional, false);
        // self.sid = Default::default();

        return result;
    }

    fn get<T: DeserializeOwned>(&self, api: &str, version: u8, method: &str, additional: &HashMap<&str, &str>, allow_cache: bool) -> Result<T, i32> {
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

                for (key, value) in &*additional {
                    url += format!("&{}={}", key, value).as_ref();
                }

                debug!("url: {}", url);

                let mut cache = self.cache.lock().unwrap();
                if !allow_cache || !cache.contains_key(url.as_str()) || cache[url.as_str()].cache_time.elapsed().unwrap() > self.cache_lifetime {
                    // Remove the key if it is in the cache.  It's expired.
                    if cache.contains_key(url.as_str()) {
                        cache.remove(url.as_str());
                    }

                    let request_time = SystemTime::now();
                    let result = reqwest::blocking::get(url.clone());

                    return match result {
                        Ok(res) => {
                            if res.status() == 200 {
                                let text_result = res.text();
    
                                match text_result {
                                    Ok(text) => {
                                        let value_result = serde_json::from_str::<serde_json::Value>(text.as_str());
    
                                        match value_result {
                                            Ok(value) => {
                                                cache.insert(url, FileStationCacheItem { cache_time: request_time, data: value.clone() });

                                                if !value["success"].as_bool().unwrap() {
                                                    error!("success: false with json '{}'.", text);
    
                                                    Err(value["error"].as_object().unwrap()["code"].as_i64().unwrap() as i32)
                                                } else {
                                                    let parsed_result = serde_json::from_value::<SynologyResult<T>>(value);
    
                                                    match parsed_result {
                                                        Ok(parsed) => Ok(parsed.data),
                                                        Err(error) => {
                                                            error!("err: {} with json '{}'.", error, text);
    
                                                            Err(-7)
                                                        } 
                                                    }
                                                }
                                            },
                                            Err(error) => {
                                                error!("err: {} with json '{}'.", error, text);
    
                                                Err(-8)
                                            }
                                        }
                                    },
                                    Err(error) => {
                                        error!("{}", error);
                                        Err(-9)
                                    }
                                }
                            }
                            else {
                                Err(res.status().as_u16() as i32)
                            }
                        },
                        Err(error) => Err(error.status().unwrap().as_u16() as i32)
                    }
                } else {
                    debug!("Using cache for url: {}.", url);
                    let parsed_result = serde_json::from_value::<SynologyResult<T>>(cache[url.as_str()].data.clone());
    
                    match parsed_result {
                        Ok(parsed) => Ok(parsed.data),
                        Err(error) => {
                            error!("err: {} with cached json.", error);

                            Err(-7)
                        } 
                    }
                }
            },
            None => Err(403)
        }
    }
}