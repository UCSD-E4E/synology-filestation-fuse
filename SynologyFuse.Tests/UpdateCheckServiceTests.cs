using System;
using SynologyFuse.Gui.Services;
using Xunit;

namespace SynologyFuse.Tests;

public class UpdateCheckServiceTests
{
    // ── TryParseTag ───────────────────────────────────────────────────────────

    [Theory]
    [InlineData("synology-filestation-fuse-v0.1.13", "0.1.13")]
    [InlineData("v0.1.13", "0.1.13")]
    [InlineData("v1.2.3.4", "1.2.3.4")]
    [InlineData("v10.20.30", "10.20.30")]
    public void TryParseTag_KnownFormats(string tag, string expected)
    {
        Assert.True(UpdateCheckService.TryParseTag(tag, out var version));
        Assert.Equal(new Version(expected), version);
    }

    [Theory]
    [InlineData("")]
    [InlineData("0.1.13")]            // missing 'v'
    [InlineData("v")]                 // 'v' with no version
    [InlineData("vNotAVersion")]
    [InlineData("v1")]                // single component
    [InlineData("v1.2.x")]            // non-numeric component
    public void TryParseTag_InvalidFormats(string tag)
    {
        Assert.False(UpdateCheckService.TryParseTag(tag, out _));
    }

    // ── EvaluateRelease: version comparison ───────────────────────────────────

    [Fact]
    public void EvaluateRelease_NewerVersion_ReturnsUpdateInfo()
    {
        var json = """
            {
                "tag_name": "synology-filestation-fuse-v0.2.0",
                "html_url": "https://github.com/UCSD-E4E/synology-filestation-fuse/releases/tag/v0.2.0"
            }
            """;

        var info = UpdateCheckService.EvaluateRelease(json, new Version("0.1.13"));

        Assert.NotNull(info);
        Assert.Equal(new Version("0.2.0"), info!.Latest);
        Assert.Equal("synology-filestation-fuse-v0.2.0", info.TagName);
        Assert.Equal(
            "https://github.com/UCSD-E4E/synology-filestation-fuse/releases/tag/v0.2.0",
            info.HtmlUrl);
    }

    [Fact]
    public void EvaluateRelease_SameVersion_ReturnsNull()
    {
        var json = """{"tag_name": "v0.1.13", "html_url": "https://example/r"}""";
        Assert.Null(UpdateCheckService.EvaluateRelease(json, new Version("0.1.13")));
    }

    [Fact]
    public void EvaluateRelease_OlderVersion_ReturnsNull()
    {
        var json = """{"tag_name": "v0.1.0", "html_url": "https://example/r"}""";
        Assert.Null(UpdateCheckService.EvaluateRelease(json, new Version("0.1.13")));
    }

    [Fact]
    public void EvaluateRelease_MissingHtmlUrl_DefaultsToEmpty()
    {
        var json = """{"tag_name": "v9.0.0"}""";
        var info = UpdateCheckService.EvaluateRelease(json, new Version("0.1.0"));

        Assert.NotNull(info);
        Assert.Equal("", info!.HtmlUrl);
    }

    // ── EvaluateRelease: malformed input ──────────────────────────────────────

    [Fact]
    public void EvaluateRelease_MalformedJson_ReturnsNull()
    {
        Assert.Null(UpdateCheckService.EvaluateRelease("{ not json }", new Version("0.0.0")));
    }

    [Fact]
    public void EvaluateRelease_EmptyObject_ReturnsNull()
    {
        Assert.Null(UpdateCheckService.EvaluateRelease("{}", new Version("0.0.0")));
    }

    [Fact]
    public void EvaluateRelease_MissingTagName_ReturnsNull()
    {
        var json = """{"html_url": "https://example/r"}""";
        Assert.Null(UpdateCheckService.EvaluateRelease(json, new Version("0.0.0")));
    }

    [Fact]
    public void EvaluateRelease_EmptyTagName_ReturnsNull()
    {
        var json = """{"tag_name": "", "html_url": "https://example/r"}""";
        Assert.Null(UpdateCheckService.EvaluateRelease(json, new Version("0.0.0")));
    }

    [Fact]
    public void EvaluateRelease_UnparseableTag_ReturnsNull()
    {
        var json = """{"tag_name": "release-2026-04-25", "html_url": "https://example/r"}""";
        Assert.Null(UpdateCheckService.EvaluateRelease(json, new Version("0.0.0")));
    }

    // ── CurrentVersion ────────────────────────────────────────────────────────

    [Fact]
    public void CurrentVersion_MatchesAssemblyVersion()
    {
        // Sanity check that the csproj <Version> property propagates to the
        // assembly. If this regresses, update checks would silently compare
        // against the manifest's 1.0.0.0 default and never find an update.
        var v = UpdateCheckService.CurrentVersion();
        Assert.True(v > new Version(0, 0, 0), $"expected non-zero version, got {v}");
    }
}
