use std::{path::PathBuf, fs, time::SystemTime};

use dirs::cache_dir;
use log::{error, debug, info};

use super::{file_station_filesystem::FileSystemInfo, epoch_from_seconds};

pub struct FileCache {
	root: PathBuf,
}

impl FileCache {
	pub fn new(hostname: &str) -> Result<FileCache, i32> {
		match cache_dir() {
			Some(mut path) => {
				path.push("Engineers for Exploration");
				path.push("synology-filestation-fuse");
				path.push(hostname);

				match fs::create_dir_all(&path) {
					Ok(_) => {
						let cache = FileCache {
							root: path
						};

						match cache.init_sqlite() {
							Ok(_) => Ok(cache),
							Err(error) => Err(error)
						}
					},
					Err(err) => {
						error!("An error occurred: {}", err);

						Err(-1)
					}
				}


			}
			None => Err(-1)
		}
	}

	pub fn is_file_cached(&self, info: &FileSystemInfo) -> bool {
		let query = "SELECT mtime FROM cached_files WHERE path = ?";
		let mtime_result = match self.get_sqlite_connection() {
			Ok(connection) =>
				connection
					.prepare(query)
					.unwrap()
					.into_iter()
					.bind((1, info.path.as_str()))
					.unwrap()
					.map(|row| row.unwrap().read::<i64, _>("mtime") as u64)
					.next(),
			Err(err) => {
				error!("An error occurred while checking if the file is cached: {}", err);

				Default::default()
			}
		};

		let cache_path = self.get_cache_path(info);
		if !cache_path.exists() {
			self.delete_cache_entry(info).unwrap();
			return false;
		}

		match mtime_result {
			Some(mtime) => {
				if info.mtime == epoch_from_seconds(mtime) {
					return true;
				}

				self.delete_cache_entry(info).unwrap();
				false
			},
			None => false
		}
	}

	pub fn get_file_cache(&self, info: &FileSystemInfo) -> Option<fs::File> {
		if self.is_file_cached(info) {
			let file = fs::File::open(self.get_cache_path(info)).unwrap();
			return Some(file);
		}

		return Default::default();
	}

	pub fn create_file_cache(&self, info: &FileSystemInfo) -> Result<fs::File, i32> {
		match self.get_sqlite_connection() {
			Ok(connection) => {
				match fs::File::create(self.get_cache_path(info)) {
					Ok(file) => {
						let query = "INSERT INTO cached_files VALUES (?, ?, ?, ?)";
						connection
							.prepare(query)
							.unwrap()
							.into_iter()
							.bind((1, info.path.as_str()))
							.unwrap()
							.bind((2, info.mtime.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64))
							.unwrap()
							.bind((3, info.size as i64))
                            .unwrap()
							.bind((4, SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64))
                            .unwrap()
							.next();

						Ok(file)
					},
					Err(error) => {
						error!("An error occurred: {}", error);

						Err(-1)
					}
				}
			},
			Err(error) => {
				error!("An error occurred: {}", error);

				Err(-1)
			}
		}
	}

	fn get_cache_path(&self, info: &FileSystemInfo) -> PathBuf {
		let mut path = self.root.clone();

		for part in info.path.split("/").into_iter() {
			path.push(part);
		}
		fs::create_dir_all(path.parent().unwrap()).unwrap();

		path
	}

	fn delete_cache_entry(&self, info: &FileSystemInfo) -> Result<(), i32> {
		match self.get_sqlite_connection() {
			Ok(connection) => {
				// Remove the invalid cache entry.
				let delete_query = "DELETE FROM cached_files WHERE path = ?";
				connection
					.prepare(delete_query)
					.unwrap()
					.into_iter()
					.bind((1, info.path.as_str()))
					.unwrap()
					.next();

				Ok(())
			},
			Err(error) => {
				error!("An error occurred while checking if the file is cached: {}", error);

				Err(-1)
			}
		}
	}

	fn get_sqlite_connection(&self) -> Result<sqlite::Connection, sqlite::Error> {
		let mut db_path = self.root.clone();
		db_path.push("cache.db");

		sqlite::open(db_path)
	}

	fn get_sqlite_version(&self, connection: &sqlite::Connection) -> u8 {
		// Check for the table.
		let table_exists_query = "SELECT name FROM sqlite_master WHERE type='table' AND name='property_bag';";
		
		// If any rows are returned, then it exists.
		let table_exists = connection
			.prepare(table_exists_query)
			.unwrap()
			.into_iter()
			.any(|_| true);
		debug!("The property bag table exists: {}", table_exists);

		if !table_exists {
			let create_table_query = "CREATE TABLE property_bag (key TEXT, value TEXT)";
			connection.execute(create_table_query).unwrap();

			let insert_version_query = "INSERT INTO property_bag VALUES ('database_version', '0');";
			connection.execute(insert_version_query).unwrap();
		}

		let database_version_query =  "SELECT value FROM property_bag WHERE key = 'database_version';";
		connection
			.prepare(database_version_query)
			.unwrap()
			.into_iter()
			.map(|rows| rows.unwrap().read::<&str, _>("value").parse::<u8>().unwrap())
			.next().unwrap()
	}

	fn init_sqlite(&self) -> Result<(), i32> {
		match self.get_sqlite_connection() {
			Ok(connection) => {
				let version: u8 = self.get_sqlite_version(&connection);
				info!("Current database version is {}.", version);

				self.init_sqlite_v1(&connection, version);

				Ok(())
			},
			Err(_err) => Err(-1)
		}
	}

	fn init_sqlite_v1(&self, connection: &sqlite::Connection, current_version: u8) -> u8 {
		if current_version >= 1 {
			// We don't need to perform this upgrade.
			return current_version;
		}

		let query = "CREATE TABLE cached_files (path TEXT, mtime INTEGER, size INTEGER, last_access INTEGER);";
		connection.execute(query).unwrap();

		self.set_sqlite_version(connection, 1)
	}

	fn set_sqlite_version(&self, connection: &sqlite::Connection, version: u8) -> u8 {
		let query = "
			UPDATE property_bag
			SET value = ?
			WHERE key = 'database_version';
		";

		connection
			.prepare(query)
			.unwrap()
			.into_iter()
			.bind((1, version.to_string().as_str()))
			.unwrap()
			.next();

		version
	}
}