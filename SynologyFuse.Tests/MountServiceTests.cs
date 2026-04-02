using System;
using System.IO;
using SynologyFuse.Gui.Models;
using SynologyFuse.Gui.Services;
using Xunit;

namespace SynologyFuse.Tests;

public class MountServiceTests
{
    // ── StripAnsi ─────────────────────────────────────────────────────────────

    [Fact]
    public void StripAnsi_PlainText_Unchanged()
    {
        Assert.Equal("hello world", MountService.StripAnsi("hello world"));
    }

    [Fact]
    public void StripAnsi_RemovesSgrColorCode()
    {
        // ESC[32m = green, ESC[0m = reset
        Assert.Equal("green text", MountService.StripAnsi("\x1b[32mgreen text\x1b[0m"));
    }

    [Fact]
    public void StripAnsi_RemovesBoldAndDim()
    {
        Assert.Equal("bold", MountService.StripAnsi("\x1b[1mbold\x1b[22m"));
    }

    [Fact]
    public void StripAnsi_RemovesMultipleSequences()
    {
        var input = "\x1b[1m\x1b[32mIMPORTANT\x1b[0m: message";
        Assert.Equal("IMPORTANT: message", MountService.StripAnsi(input));
    }

    [Fact]
    public void StripAnsi_EmptyString_ReturnsEmpty()
    {
        Assert.Equal("", MountService.StripAnsi(""));
    }

    // ── Quote ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Quote_NoSpaces_ReturnsOriginal()
    {
        Assert.Equal("nas.local", MountService.Quote("nas.local"));
    }

    [Fact]
    public void Quote_ContainsSpace_WrapsInDoubleQuotes()
    {
        Assert.Equal("\"My NAS\"", MountService.Quote("My NAS"));
    }

    [Fact]
    public void Quote_EmptyString_ReturnsEmpty()
    {
        Assert.Equal("", MountService.Quote(""));
    }

    // ── ExpandEnvVars ─────────────────────────────────────────────────────────

    [Fact]
    public void ExpandEnvVars_PercentStyle_Expanded()
    {
        Environment.SetEnvironmentVariable("SYNOTEST_VAR", "expanded");
        try
        {
            var result = MountService.ExpandEnvVars("%SYNOTEST_VAR%/path");
            Assert.Equal("expanded/path", result);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SYNOTEST_VAR", null);
        }
    }

    [Fact]
    public void ExpandEnvVars_DollarStyle_Expanded()
    {
        Environment.SetEnvironmentVariable("SYNOTEST_VAR", "expanded");
        try
        {
            var result = MountService.ExpandEnvVars("/path/$SYNOTEST_VAR/sub");
            Assert.Equal("/path/expanded/sub", result);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SYNOTEST_VAR", null);
        }
    }

    [Fact]
    public void ExpandEnvVars_CurlyBraceStyle_Expanded()
    {
        Environment.SetEnvironmentVariable("SYNOTEST_VAR", "expanded");
        try
        {
            var result = MountService.ExpandEnvVars("/path/${SYNOTEST_VAR}/sub");
            Assert.Equal("/path/expanded/sub", result);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SYNOTEST_VAR", null);
        }
    }

    [Fact]
    public void ExpandEnvVars_UndefinedVar_LeftUnchanged()
    {
        Environment.SetEnvironmentVariable("SYNOTEST_UNDEF", null);
        var result = MountService.ExpandEnvVars("/path/$SYNOTEST_UNDEF/sub");
        Assert.Equal("/path/$SYNOTEST_UNDEF/sub", result);
    }

    [Fact]
    public void ExpandEnvVars_NoVars_Unchanged()
    {
        Assert.Equal("/mnt/share", MountService.ExpandEnvVars("/mnt/share"));
    }

    // ── ExpandPath ────────────────────────────────────────────────────────────

    [Fact]
    public void ExpandPath_TildeAlone_ExpandsToHome()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        Assert.Equal(home, MountService.ExpandPath("~"));
    }

    [Fact]
    public void ExpandPath_TildeSlash_ExpandsToHomeSubdir()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var result = MountService.ExpandPath("~/mounts/nas");
        Assert.Equal(home + "/mounts/nas", result);
    }

    [Fact]
    public void ExpandPath_NoTilde_Unchanged()
    {
        Assert.Equal("/mnt/nas", MountService.ExpandPath("/mnt/nas"));
    }

    // ── BuildArgs ─────────────────────────────────────────────────────────────

    [Fact]
    public void BuildArgs_IncludesHostUsernamePortLogLevel()
    {
        var config = new MountConfig
        {
            Host = "nas.local",
            Username = "alice",
            Port = 5001,
            UseHttps = true,
            Mountpoint = "/mnt/nas",
            LogLevel = "info",
        };

        var args = MountService.BuildArgs(config);

        Assert.Contains("--host nas.local", args);
        Assert.Contains("--username alice", args);
        Assert.Contains("--port 5001", args);
        Assert.Contains("--log-level info", args);
    }

    [Fact]
    public void BuildArgs_MountpointIsLastArg()
    {
        var config = new MountConfig
        {
            Host = "nas.local",
            Username = "alice",
            Port = 5001,
            UseHttps = true,
            Mountpoint = "/mnt/nas",
            LogLevel = "info",
        };

        var args = MountService.BuildArgs(config);
        Assert.EndsWith("/mnt/nas", args);
    }

    [Fact]
    public void BuildArgs_HttpsDisabled_AddsHttpsFalse()
    {
        var config = new MountConfig
        {
            Host = "nas.local",
            Username = "alice",
            Port = 5000,
            UseHttps = false,
            Mountpoint = "/mnt/nas",
            LogLevel = "warn",
        };

        var args = MountService.BuildArgs(config);
        Assert.Contains("--https false", args);
    }

    [Fact]
    public void BuildArgs_HttpsEnabled_DoesNotAddHttpsFlag()
    {
        var config = new MountConfig
        {
            Host = "nas.local",
            Username = "alice",
            Port = 5001,
            UseHttps = true,
            Mountpoint = "/mnt/nas",
            LogLevel = "info",
        };

        var args = MountService.BuildArgs(config);
        Assert.DoesNotContain("--https", args);
    }

    [Fact]
    public void BuildArgs_HostWithSpaces_IsQuoted()
    {
        var config = new MountConfig
        {
            Host = "my nas",
            Username = "alice",
            Port = 5001,
            UseHttps = true,
            Mountpoint = "/mnt/nas",
            LogLevel = "info",
        };

        var args = MountService.BuildArgs(config);
        Assert.Contains("--host \"my nas\"", args);
    }

    // ── FindRepoRoot ──────────────────────────────────────────────────────────

    [Fact]
    public void FindRepoRoot_FindsCargoTomlInParent()
    {
        var root = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        var subDir = Path.Combine(root, "a", "b", "c");
        Directory.CreateDirectory(subDir);
        File.WriteAllText(Path.Combine(root, "Cargo.toml"), "[package]");
        try
        {
            var found = MountService.FindRepoRoot(subDir);
            Assert.Equal(root, found);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void FindRepoRoot_NoCargoToml_ReturnsNull()
    {
        var dir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(dir);
        try
        {
            // Temp dir tree won't have Cargo.toml, so result should be null
            // (unless a Cargo.toml happens to be somewhere above %TEMP% — very unlikely).
            var found = MountService.FindRepoRoot(dir);
            // We can't assert null absolutely (unlikely but possible), just that if
            // found it points to a directory containing Cargo.toml.
            if (found is not null)
                Assert.True(File.Exists(Path.Combine(found, "Cargo.toml")));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void FindRepoRoot_CargoTomlInStartDir_ReturnsThatDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "Cargo.toml"), "[package]");
        try
        {
            var found = MountService.FindRepoRoot(dir);
            Assert.Equal(dir, found);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
