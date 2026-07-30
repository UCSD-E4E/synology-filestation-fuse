using System.Collections.Generic;
using System.Threading.Tasks;
using SynologyFuse.Gui.Models;
using SynologyFuse.Gui.Services;
using SynologyFuse.Gui.ViewModels;
using Xunit;

namespace SynologyFuse.Tests;

/// <summary>
/// Covers the browser's clipboard surface. These commands never touch the
/// native client, so they exercise cleanly without a NAS session.
/// </summary>
public class FileBrowserViewModelTests
{
    private sealed class FakeClipboard : IClipboardService
    {
        public List<string> Writes { get; } = new();
        public string? Last => Writes.Count == 0 ? null : Writes[^1];
        public Task SetTextAsync(string text)
        {
            Writes.Add(text);
            return Task.CompletedTask;
        }
    }

    private static (FileBrowserViewModel Vm, FakeClipboard Clip) NewVm()
    {
        var clip = new FakeClipboard();
        return (new FileBrowserViewModel(new MountConfig(), clip), clip);
    }

    // ── Current path (the browser's path bar / window title) ───────────────────

    [Fact]
    public async Task CopyCurrentPath_CopiesTheCurrentDirectory()
    {
        var (vm, clip) = NewVm();
        vm.CurrentPath = "/photos/2026";

        await vm.CopyCurrentPathCommand.ExecuteAsync(null);

        Assert.Equal("/photos/2026", clip.Last);
    }

    [Fact]
    public void CopyCurrentPath_DisabledAtSharesRoot()
    {
        var (vm, _) = NewVm();
        vm.CurrentPath = "";

        Assert.False(vm.CopyCurrentPathCommand.CanExecute(null));
    }

    [Fact]
    public void CopyCurrentPath_ReenabledWhenPathChanges()
    {
        var (vm, _) = NewVm();
        vm.CurrentPath = "";
        Assert.False(vm.CopyCurrentPathCommand.CanExecute(null));

        vm.CurrentPath = "/photos";

        Assert.True(vm.CopyCurrentPathCommand.CanExecute(null));
    }

    [Fact]
    public async Task CopyCurrentPath_NoClipboard_DoesNotThrow()
    {
        var vm = new FileBrowserViewModel(new MountConfig()) { CurrentPath = "/photos" };

        await vm.CopyCurrentPathCommand.ExecuteAsync(null);
    }

    // ── Selected item (right-click on a file or folder) ────────────────────────

    [Fact]
    public async Task CopySelectedPath_CopiesFullPathOfSelection()
    {
        var (vm, clip) = NewVm();
        vm.CurrentPath = "/photos";
        vm.SelectedItem = new SynoFileInfo { Name = "raw.ORF", Path = "/photos/raw.ORF" };

        await vm.CopySelectedPathCommand.ExecuteAsync(null);

        Assert.Equal("/photos/raw.ORF", clip.Last);
    }

    [Fact]
    public async Task CopySelectedPath_WorksForDirectories()
    {
        var (vm, clip) = NewVm();
        vm.SelectedItem = new SynoFileInfo { Name = "2026", Path = "/photos/2026", IsDir = true };

        await vm.CopySelectedPathCommand.ExecuteAsync(null);

        Assert.Equal("/photos/2026", clip.Last);
    }

    [Fact]
    public async Task CopySelectedName_CopiesJustTheName()
    {
        var (vm, clip) = NewVm();
        vm.SelectedItem = new SynoFileInfo { Name = "raw.ORF", Path = "/photos/raw.ORF" };

        await vm.CopySelectedNameCommand.ExecuteAsync(null);

        Assert.Equal("raw.ORF", clip.Last);
    }

    [Fact]
    public void CopySelected_DisabledWithNoSelection()
    {
        var (vm, _) = NewVm();

        Assert.False(vm.CopySelectedPathCommand.CanExecute(null));
        Assert.False(vm.CopySelectedNameCommand.CanExecute(null));
    }

    [Fact]
    public void CopySelected_EnabledOnceAnItemIsSelected()
    {
        var (vm, _) = NewVm();

        vm.SelectedItem = new SynoFileInfo { Name = "raw.ORF", Path = "/photos/raw.ORF" };

        Assert.True(vm.CopySelectedPathCommand.CanExecute(null));
        Assert.True(vm.CopySelectedNameCommand.CanExecute(null));
    }

    // ── Feedback ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Copy_ReportsWhatWasCopiedInTheStatusLine()
    {
        var (vm, _) = NewVm();
        vm.SelectedItem = new SynoFileInfo { Name = "raw.ORF", Path = "/photos/raw.ORF" };

        await vm.CopySelectedPathCommand.ExecuteAsync(null);

        Assert.Contains("/photos/raw.ORF", vm.Status);
    }

    // ── Window title ──────────────────────────────────────────────────────────

    [Fact]
    public void Title_ShowsSharesRootWhenNoPath()
    {
        var (vm, _) = NewVm();
        vm.CurrentPath = "";

        Assert.Equal("Browse NAS", vm.Title);
    }

    [Fact]
    public void Title_TracksCurrentPath()
    {
        var (vm, _) = NewVm();

        vm.CurrentPath = "/photos/2026";

        Assert.Equal("Browse NAS — /photos/2026", vm.Title);
    }
}
