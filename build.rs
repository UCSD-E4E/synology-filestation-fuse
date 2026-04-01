fn main() {
    // On Windows, configure delay-loading of winfsp-x64.dll so the binary can
    // start (e.g. to print --help) even when WinFsp is not installed.
    // The DLL is only required at runtime when the filesystem is actually mounted.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winfsp::build::winfsp_link_delayload();
    }
}
