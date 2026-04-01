fn main() {
    // On Windows, configure delay-loading of winfsp-x64.dll so the binary can
    // start (e.g. to print --help) even when WinFsp is not installed.
    // The DLL is only required at runtime when the filesystem is actually mounted.
    #[cfg(target_os = "windows")]
    winfsp::build::winfsp_link_delayload();
}
