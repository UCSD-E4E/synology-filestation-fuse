use super::FileStation;

pub struct FileStationFileSystem {
    pub filestation: FileStation,
}

impl FileStationFileSystem {
    pub fn new(hostname: &str, port: u16, secured: bool, version: u8) -> FileStationFileSystem {
        FileStationFileSystem {
            filestation: FileStation::new(hostname, port, secured, version)
        }
    }

    pub fn login(&mut self, username: &str, password: &str) -> Result<(), i32> {
        self.filestation.login(username, password)
    }
}