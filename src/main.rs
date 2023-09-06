use std::io::{stdin, stdout, Read, Write};
use filesystems::FuseFileSystem;

mod filesystems;
mod synology_api;


fn pause() {
    let mut stdout = stdout();
    stdout.write(b"Press Enter to continue...").unwrap();
    stdout.flush().unwrap();
    stdin().read(&mut [0]).unwrap();
}

fn main() {
    let mut fuse_fileystem = filesystems::WindowsFuseFileSystem::new(
        "",
        0,
        true,
        0
    );

    println!("Mounting Synology NAS...");

    fuse_fileystem.mount("Q:", "", "");

    // Wait here until a user presses a key...
    pause();

    println!("Unmounting Synology NAS...");
    fuse_fileystem.unmount();
}
