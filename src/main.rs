use std::env;
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

#[cfg(target_family = "windows")]
fn init_fuse_filesystem(hostname: &str, port: u16, secured: bool, version: u8, debug_mode: bool) -> filesystems::WindowsFuseFileSystem {
    filesystems::WindowsFuseFileSystem::new(
        hostname,
        port,
        secured,
        version,
        debug_mode
    )
}

#[cfg(target_family = "unix")]
fn init_fuse_filesystem(hostname: &str, port: u16, secured: bool, version: u8, debug_mode: bool) -> filesystems::UnixFuseFileSystem {
    filesystems::UnixFuseFileSystem::new(
        hostname,
        port,
        secured,
        version,
        debug_mode
    )
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let debug_mode = args[1] == "--debug";

    let hostname: String;
    let port: u16;
    let secured: bool;
    let version: u8;

    let mountpoint: String;
    let username: String;
    let password: String;

    if debug_mode {
        println!("Running in debug mode...");

        hostname = env::var("SYNOLOGY_HOSTNAME").unwrap();
        port = env::var("SYNOLOGY_PORT").unwrap().parse::<u16>().unwrap();
        secured = env::var("SYNOLOGY_SECURED").unwrap().parse::<bool>().unwrap();
        version = env::var("SYNOLOGY_VERSION").unwrap().parse::<u8>().unwrap();

        mountpoint = env::var("SYNOLOGY_MOUNTPOINT").unwrap();
        username = env::var("SYNOLOGY_USERNAME").unwrap();
        password = env::var("SYNOLOGY_PASSWORD").unwrap();
    } else {
        hostname = "".to_string();
        port = 0;
        secured = true;
        version = 0;

        mountpoint = "".to_string();
        username = "".to_string();
        password = "".to_string();
    }

    let mut fuse_fileystem = init_fuse_filesystem(
        &hostname,
        port,
        secured,
        version,
        debug_mode);

    println!("Mounting Synology NAS...");

    fuse_fileystem.mount(&mountpoint, &username, &password);

    if !debug_mode {
        // Wait here until a user presses a key...
        pause();
    }

    println!("Unmounting Synology NAS...");
    fuse_fileystem.unmount();
}
