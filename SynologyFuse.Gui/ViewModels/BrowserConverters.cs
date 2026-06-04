using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace SynologyFuse.Gui.ViewModels;

/// <summary>Small value converters for the file-browser listing.</summary>
public static class BrowserConverters
{
    /// <summary>bool IsDir → a folder/file glyph.</summary>
    public static readonly IValueConverter DirGlyph =
        new FuncValueConverter<bool, string>(isDir => isDir ? "📁" : "📄");

    /// <summary>Nullable byte count → human-readable size ("" for directories/unknown).</summary>
    public static readonly IValueConverter Size =
        new FuncValueConverter<ulong?, string>(size => size is { } n ? HumanSize((long)n) : "");

    /// <summary>Format a byte count as a human-readable size (binary units).
    /// Shared by the listing's Size column and the transfer-progress label.</summary>
    public static string HumanSize(long n)
    {
        string[] units = ["B", "KiB", "MiB", "GiB", "TiB"];
        double v = n;
        int u = 0;
        while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
        return $"{v:0.#} {units[u]}";
    }
}
