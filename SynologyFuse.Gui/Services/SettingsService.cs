using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

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

    /// <summary>NetBIOS domain the account lives in (`KRG` for an AD account).
    /// Empty for a local DSM user. Used by both SMB and the VPN.</summary>
    public string Domain { get; set; } = "";

    /// <summary>The name <see cref="Domain"/> had while SMB was the only leg
    /// that authenticated against the directory. Read so a settings.json
    /// written before the rename keeps its value, and never written back — the
    /// migration in <see cref="SettingsService.Load"/> clears it.
    ///
    /// Worth the twelve lines: an empty domain sends an unqualified name, DSM
    /// refuses it before checking the password, and DSM's auto-block is three
    /// strikes in 24 hours that never expire.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SmbDomain { get; set; }

    /// <summary>Where the OpenVPN profile is kept, if the NAS should be reached
    /// through a tunnel when it does not answer directly.</summary>
    public string VpnProfile { get; set; } = "";

    /// <summary>The NAS's address inside that tunnel.</summary>
    public string VpnHost { get; set; } = "";

    /// <summary>The same profile's path on the NAS, to download it from when
    /// there is no copy on this computer yet. Empty to use only what is
    /// already here.</summary>
    public string VpnProfileNas { get; set; } = "";
}

public static class SettingsService
{
    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "SynologyFuse",
        "settings.json");

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    /// <summary>Where a downloaded VPN profile is kept, beside the settings.
    ///
    /// Chosen for the user rather than asked of them. The profile has two
    /// locations — where it lives on the NAS and where the copy is kept here —
    /// and a single field asking for "the VPN profile" invites the first,
    /// which is a path this machine cannot write to.</summary>
    public static string DefaultVpnProfilePath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "SynologyFuse",
        "vpn-profile.ovpn");

    /// <summary>Where to keep the profile for this connection, or null when no
    /// tunnel is wanted.
    ///
    /// A tunnel needs somewhere inside it to go, so <paramref name="vpnHost"/>
    /// is what says one is wanted at all. Then either the profile is already on
    /// this computer — <paramref name="localPath"/> — or it is on the NAS at
    /// <paramref name="nasPath"/>, in which case it is downloaded and kept
    /// <see cref="DefaultVpnProfilePath">alongside the settings</see>.
    ///
    /// The two are asked separately because they are different places, and one
    /// field asking for "the VPN profile" invites the NAS's path into a
    /// setting that names a file on this disk.</summary>
    public static string? ResolveVpnProfile(string? localPath, string? nasPath, string? vpnHost)
    {
        if (string.IsNullOrWhiteSpace(vpnHost)) return null;
        if (!string.IsNullOrWhiteSpace(localPath)) return localPath;
        // Somewhere to put what is about to be downloaded. Only meaningful if
        // there is somewhere to download it from: without either, there is no
        // profile and no tunnel.
        return string.IsNullOrWhiteSpace(nasPath) ? null : DefaultVpnProfilePath;
    }

    public static PersistedSettings Load(string? path = null)
    {
        var filePath = path ?? SettingsPath;
        try
        {
            if (File.Exists(filePath))
            {
                var json = File.ReadAllText(filePath);
                return Migrated(JsonSerializer.Deserialize<PersistedSettings>(json) ?? new());
            }
        }
        catch { /* corrupt file — fall back to defaults */ }

        return new();
    }

    /// <summary>Carry a pre-rename file forward, once.
    ///
    /// The current key wins where both are present: a file written since the
    /// rename is the authority on its own value, and the stale key beside it
    /// is not a second opinion. Clearing it afterwards is what stops the old
    /// name living on in every settings file that has ever been saved.</summary>
    private static PersistedSettings Migrated(PersistedSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.Domain)
            && !string.IsNullOrWhiteSpace(settings.SmbDomain))
        {
            settings.Domain = settings.SmbDomain;
        }

        settings.SmbDomain = null;
        return settings;
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
