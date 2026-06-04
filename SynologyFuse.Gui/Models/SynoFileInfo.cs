using System.Text.Json.Serialization;

namespace SynologyFuse.Gui.Models;

/// <summary>
/// A file or directory entry returned by the native browse calls. Deserialized
/// from the stable flat JSON shape emitted by the FFI (<c>fileinfo_json</c>):
/// keys are always present, with nulls for missing metadata.
/// </summary>
public sealed record SynoFileInfo
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("path")] public string Path { get; init; } = "";
    [JsonPropertyName("isdir")] public bool IsDir { get; init; }
    [JsonPropertyName("size")] public ulong? Size { get; init; }
    [JsonPropertyName("mtime")] public long? Mtime { get; init; }
    [JsonPropertyName("atime")] public long? Atime { get; init; }
    [JsonPropertyName("ctime")] public long? Ctime { get; init; }
    [JsonPropertyName("perm")] public uint? Perm { get; init; }
}
