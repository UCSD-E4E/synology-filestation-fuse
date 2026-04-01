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

    public static PersistedSettings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var json = File.ReadAllText(SettingsPath);
                return JsonSerializer.Deserialize<PersistedSettings>(json) ?? new();
            }
        }
        catch { /* corrupt file — fall back to defaults */ }

        return new();
    }

    public static void Save(PersistedSettings settings)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(settings, JsonOptions));
        }
        catch { /* non-fatal — best effort */ }
    }
}
