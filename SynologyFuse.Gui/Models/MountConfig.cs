namespace SynologyFuse.Gui.Models;

public sealed class MountConfig
{
    public string Host { get; init; } = "";
    public string Username { get; init; } = "";
    public string Password { get; init; } = "";
    public ushort Port { get; init; } = 5001;
    public bool UseHttps { get; init; } = true;

    /// <summary>Verify the NAS TLS certificate. Turn off only for a self-signed
    /// DSM certificate -- the connection is then encrypted but not authenticated.
    /// Absent from an older settings file, the initialiser keeps it on.</summary>
    public bool VerifySsl { get; init; } = true;
    public string Mountpoint { get; init; } = "";
    public ulong CacheTtl { get; init; } = 30;
    public ulong ReadCacheMb { get; init; } = 256;
    public string LogLevel { get; init; } = "info";

    /// <summary>NetBIOS domain SMB authenticates in -- `KRG` for an AD account,
    /// empty for a local DSM user. Without it an AD account is checked against
    /// the appliance's own accounts, fails, and SMB is silently skipped in
    /// favour of the slower HTTP path.</summary>
    public string Domain { get; init; } = "";

    /// <summary>Where the OpenVPN profile is kept. Given it, a NAS that does
    /// not answer directly is reached through a tunnel raised inside this
    /// process -- no tun device, no privileged helper, and no effect on
    /// anything else the machine is doing. Fetched from the NAS if the file is
    /// not there.</summary>
    public string VpnProfile { get; init; } = "";

    /// <summary>The NAS's address inside that tunnel, which its public name
    /// does not resolve to: the tunnel pushes no DNS.</summary>
    public string VpnHost { get; init; } = "";

    /// <summary>The same profile's path on the NAS, to download it from when
    /// there is no copy on this computer yet. Empty to use only what is
    /// already here.</summary>
    public string VpnProfileNas { get; init; } = "";
}
