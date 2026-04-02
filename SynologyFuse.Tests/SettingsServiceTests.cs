using System;
using System.IO;
using System.Text.Json;
using SynologyFuse.Gui.Services;
using Xunit;

namespace SynologyFuse.Tests;

public class SettingsServiceTests : IDisposable
{
    private readonly string _dir;
    private readonly string _path;

    public SettingsServiceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "settings.json");
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    // ── Load ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Load_FileDoesNotExist_ReturnsDefaults()
    {
        var s = SettingsService.Load(_path);

        Assert.Equal("", s.Host);
        Assert.Equal("", s.Username);
        Assert.Equal(5001m, s.Port);
        Assert.True(s.UseHttps);
        Assert.Equal("info", s.LogLevel);
    }

    [Fact]
    public void Load_ValidJson_ReturnsPersistedValues()
    {
        File.WriteAllText(_path, """
            {
                "Host": "nas.example.com",
                "Username": "bob",
                "Port": 5000,
                "UseHttps": false,
                "Mountpoint": "/mnt/nas",
                "CacheTtl": 60,
                "ReadCacheMb": 512,
                "LogLevel": "debug"
            }
            """);

        var s = SettingsService.Load(_path);

        Assert.Equal("nas.example.com", s.Host);
        Assert.Equal("bob", s.Username);
        Assert.Equal(5000m, s.Port);
        Assert.False(s.UseHttps);
        Assert.Equal("/mnt/nas", s.Mountpoint);
        Assert.Equal(60m, s.CacheTtl);
        Assert.Equal(512m, s.ReadCacheMb);
        Assert.Equal("debug", s.LogLevel);
    }

    [Fact]
    public void Load_CorruptJson_ReturnsDefaults()
    {
        File.WriteAllText(_path, "{ this is not valid json }}}");

        var s = SettingsService.Load(_path);

        Assert.Equal("", s.Host);
        Assert.Equal("info", s.LogLevel);
    }

    [Fact]
    public void Load_PartialJson_MissingFieldsUseDefaults()
    {
        File.WriteAllText(_path, """{"Host": "partial.host"}""");

        var s = SettingsService.Load(_path);

        Assert.Equal("partial.host", s.Host);
        Assert.Equal("", s.Username);   // default
        Assert.Equal("info", s.LogLevel); // default
    }

    // ── Save ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Save_WritesValidJson()
    {
        var settings = new PersistedSettings
        {
            Host = "mynas.local",
            Username = "alice",
            Port = 5001m,
            UseHttps = true,
            Mountpoint = "/mnt/mynas",
            CacheTtl = 45m,
            ReadCacheMb = 128m,
            LogLevel = "warn",
        };

        SettingsService.Save(settings, _path);

        Assert.True(File.Exists(_path));
        var json = File.ReadAllText(_path);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal("mynas.local", root.GetProperty("Host").GetString());
        Assert.Equal("alice", root.GetProperty("Username").GetString());
        Assert.Equal(5001m, root.GetProperty("Port").GetDecimal());
        Assert.True(root.GetProperty("UseHttps").GetBoolean());
        Assert.Equal("warn", root.GetProperty("LogLevel").GetString());
    }

    [Fact]
    public void Save_CreatesParentDirectories()
    {
        var deepPath = Path.Combine(_dir, "nested", "deep", "settings.json");
        SettingsService.Save(new PersistedSettings(), deepPath);
        Assert.True(File.Exists(deepPath));
    }

    // ── Round-trip ────────────────────────────────────────────────────────────

    [Fact]
    public void SaveThenLoad_RoundTrips()
    {
        var original = new PersistedSettings
        {
            Host = "roundtrip.nas",
            Username = "carol",
            Port = 5002m,
            UseHttps = false,
            Mountpoint = "/data",
            CacheTtl = 10m,
            ReadCacheMb = 64m,
            LogLevel = "trace",
        };

        SettingsService.Save(original, _path);
        var loaded = SettingsService.Load(_path);

        Assert.Equal(original.Host, loaded.Host);
        Assert.Equal(original.Username, loaded.Username);
        Assert.Equal(original.Port, loaded.Port);
        Assert.Equal(original.UseHttps, loaded.UseHttps);
        Assert.Equal(original.Mountpoint, loaded.Mountpoint);
        Assert.Equal(original.CacheTtl, loaded.CacheTtl);
        Assert.Equal(original.ReadCacheMb, loaded.ReadCacheMb);
        Assert.Equal(original.LogLevel, loaded.LogLevel);
    }
}
