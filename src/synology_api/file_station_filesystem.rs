use super::FileStation;

pub struct FileStationFileSystem {
    file_station: FileStation,
}

impl FileStationFileSystem {
    pub fn new(hostname: &str, port: u16, secured: bool, version: u8) -> FileStationFileSystem {
        FileStationFileSystem {
            file_station: FileStation::new(hostname, port, secured, version)
        }
    }
}