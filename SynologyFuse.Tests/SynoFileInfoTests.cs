using System.Text.Json;
using SynologyFuse.Gui.Models;
using Xunit;

namespace SynologyFuse.Tests;

/// <summary>
/// Verifies the C# side deserializes the flat JSON shape the FFI emits
/// (<c>fileinfo_json</c> in the Rust crate): keys always present, nulls for
/// missing metadata.
/// </summary>
public class SynoFileInfoTests
{
    private static readonly JsonSerializerOptions Opts = new() { PropertyNameCaseInsensitive = true };

    [Fact]
    public void Deserializes_FullEntry()
    {
        const string json = """
            {"name":"report.pdf","path":"/home/report.pdf","isdir":false,
             "size":2048,"mtime":1700000000,"atime":1700000001,"ctime":1700000002,"perm":420}
            """;

        var info = JsonSerializer.Deserialize<SynoFileInfo>(json, Opts)!;

        Assert.Equal("report.pdf", info.Name);
        Assert.Equal("/home/report.pdf", info.Path);
        Assert.False(info.IsDir);
        Assert.Equal(2048UL, info.Size);
        Assert.Equal(1700000000L, info.Mtime);
        Assert.Equal(420U, info.Perm);
    }

    [Fact]
    public void Deserializes_DirectoryWithNullMetadata()
    {
        const string json = """
            {"name":"home","path":"/home","isdir":true,
             "size":null,"mtime":null,"atime":null,"ctime":null,"perm":null}
            """;

        var info = JsonSerializer.Deserialize<SynoFileInfo>(json, Opts)!;

        Assert.Equal("home", info.Name);
        Assert.True(info.IsDir);
        Assert.Null(info.Size);
        Assert.Null(info.Mtime);
        Assert.Null(info.Perm);
    }

    [Fact]
    public void Deserializes_Array()
    {
        const string json = """
            [{"name":"a","path":"/a","isdir":true,"size":null,"mtime":null,"atime":null,"ctime":null,"perm":null},
             {"name":"b.txt","path":"/b.txt","isdir":false,"size":10,"mtime":null,"atime":null,"ctime":null,"perm":null}]
            """;

        var items = JsonSerializer.Deserialize<SynoFileInfo[]>(json, Opts)!;

        Assert.Equal(2, items.Length);
        Assert.True(items[0].IsDir);
        Assert.Equal(10UL, items[1].Size);
    }
}
