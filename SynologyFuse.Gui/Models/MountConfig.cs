namespace SynologyFuse.Gui.Models;

public sealed class MountConfig
{
    public string Host { get; init; } = "";
    public string Username { get; init; } = "";
    public string Password { get; init; } = "";
    public ushort Port { get; init; } = 5001;
    public bool UseHttps { get; init; } = true;
    public string Mountpoint { get; init; } = "";
    public ulong CacheTtl { get; init; } = 30;
    public ulong ReadCacheMb { get; init; } = 256;
    public string LogLevel { get; init; } = "info";
}
