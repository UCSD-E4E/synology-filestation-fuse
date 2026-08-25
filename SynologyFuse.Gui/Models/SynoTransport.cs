namespace SynologyFuse.Gui.Models;

/// <summary>
/// Which leg a connection reaches the NAS by. Mirrors the Rust
/// <c>SynoTransport</c> enum, and is settled when the connection is made.
///
/// Ordered worst to best deliberately, so a badge can compare them without
/// knowing what any of them mean.
/// </summary>
public enum SynoTransport
{
    /// <summary>Reported for a null handle: nothing has connected yet.</summary>
    Unknown = -1,

    /// <summary>The HTTP FileStation API. Works from anywhere the DSM port is
    /// open, and cannot resume an interrupted transfer.</summary>
    Https = 0,

    /// <summary>SMB through a tunnel this process raised — no tun device, no
    /// privileged helper.</summary>
    SmbOverVpn = 1,

    /// <summary>SMB straight to the appliance.</summary>
    SmbDirect = 2,
}
