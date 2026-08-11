using System;
using System.IO;
using System.Text.Json;

namespace SynologyFuse.Gui.Services;

/// <summary>
/// Fields persisted across sessions. Password and OTP are intentionally excluded.
/// </summary>
public sealed class PersistedSettings
{
    public string Host { get; set; } = "";
    public string Username { get; set; } = "";
    public decimal Port { get; set; } = 5001;
    public bool UseHttps { get; set; } = true;

    /// <summary>
    /// Verify the NAS TLS certificate. Defaults to true, and because
    /// System.Text.Json only assigns properties actually present in the file,
    /// a settings.json written before this option existed deserializes as
    /// verifying — the secure value, not <c>default(bool)</c>.
    /// </summary>
    public bool VerifySsl { get; set; } = true;
    public string Mountpoint { get; set; } = "";
    public decimal CacheTtl { get; set; } = 30;
    public decimal ReadCacheMb { get; set; } = 256;
    public string LogLevel { get; set; } = "info";
}

public static class SettingsService
{
    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "SynologyFuse",
        "settings.json");

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static PersistedSettings Load(string? path = null)
    {
        var filePath = path ?? SettingsPath;
        try
        {
            if (File.Exists(filePath))
            {
                var json = File.ReadAllText(filePath);
                return JsonSerializer.Deserialize<PersistedSettings>(json) ?? new();
            }
        }
        catch { /* corrupt file — fall back to defaults */ }

        return new();
    }

    public static void Save(PersistedSettings settings, string? path = null)
    {
        var filePath = path ?? SettingsPath;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
            File.WriteAllText(filePath, JsonSerializer.Serialize(settings, JsonOptions));
        }
        catch { /* non-fatal — best effort */ }
    }
}
