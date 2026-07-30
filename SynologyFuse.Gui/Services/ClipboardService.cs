using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Input.Platform; // SetTextAsync moved to ClipboardExtensions in Avalonia 12

namespace SynologyFuse.Gui.Services;

/// <summary>
/// Minimal clipboard surface used by the view models. Abstracted away from
/// Avalonia's <see cref="Avalonia.Input.Platform.IClipboard"/> so copy commands
/// are testable without a windowing system.
/// </summary>
public interface IClipboardService
{
    Task SetTextAsync(string text);
}

/// <summary>
/// Writes to the clipboard of a live window. The <see cref="TopLevel"/>'s
/// clipboard is resolved per call — it is null until the window has a platform
/// implementation, which happens after construction.
/// </summary>
public sealed class ClipboardService : IClipboardService
{
    private readonly TopLevel _topLevel;

    public ClipboardService(TopLevel topLevel) => _topLevel = topLevel;

    public Task SetTextAsync(string text) =>
        _topLevel.Clipboard?.SetTextAsync(text) ?? Task.CompletedTask;
}
