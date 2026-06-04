using System;
using System.IO;
using SynologyFuse.Gui.Interop;
using SynologyFuse.Gui.Services;
using Xunit;

namespace SynologyFuse.Tests;

public class MountServiceTests
{
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

    // ── NativeMethods.FindRepoRoot (native-library resolver) ────────────────────

    [Fact]
    public void FindRepoRoot_FindsCargoTomlInParent()
    {
        var root = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        var subDir = Path.Combine(root, "a", "b", "c");
        Directory.CreateDirectory(subDir);
        File.WriteAllText(Path.Combine(root, "Cargo.toml"), "[package]");
        try
        {
            var found = NativeMethods.FindRepoRoot(subDir);
            Assert.Equal(root, found);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
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
            var found = NativeMethods.FindRepoRoot(dir);
            Assert.Equal(dir, found);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
