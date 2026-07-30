using System;
using System.Linq;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.VisualTree;
using SynologyFuse.Gui.Models;
using SynologyFuse.Gui.Services;
using SynologyFuse.Gui.ViewModels;

namespace SynologyFuse.Gui.Views;

public partial class FileBrowserWindow : Window
{
    public FileBrowserWindow() => InitializeComponent();

    public FileBrowserWindow(MountConfig config) : this()
    {
        var vm = new FileBrowserViewModel(config, new ClipboardService(this));
        DataContext = vm;
        Opened += async (_, _) => await vm.ConnectAsync();
        Closed += (_, _) => vm.Dispose();
    }

    private FileBrowserViewModel? Vm => DataContext as FileBrowserViewModel;

    private async void OnItemDoubleTapped(object? sender, TappedEventArgs e)
    {
        if (Vm is { } vm && vm.OpenCommand.CanExecute(null))
            await vm.OpenCommand.ExecuteAsync(null);
    }

    /// <summary>Right-clicking an entry acts on that entry: select it before the
    /// context menu opens, so the copy/download/delete commands target it.</summary>
    private void OnListContextRequested(object? sender, ContextRequestedEventArgs e)
    {
        if (Vm is not { } vm) return;
        if (e.Source is Visual source &&
            source.FindAncestorOfType<ListBoxItem>(includeSelf: true) is { DataContext: SynoFileInfo item })
        {
            vm.SelectedItem = item;
        }
    }

    private async void OnDownload(object? sender, RoutedEventArgs e)
    {
        if (Vm is not { SelectedItem: { IsDir: false } item } vm) return;

        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Download to…",
            SuggestedFileName = item.Name,
        });
        if (file?.TryGetLocalPath() is { } local)
            await vm.DownloadAsync(item, local);
    }

    private async void OnUpload(object? sender, RoutedEventArgs e)
    {
        if (Vm is not { } vm) return;

        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Upload file",
            AllowMultiple = false,
        });
        if (files.FirstOrDefault()?.TryGetLocalPath() is { } local)
            await vm.UploadAsync(local);
    }

    private async void OnNewFolder(object? sender, RoutedEventArgs e)
    {
        if (Vm is not { } vm) return;
        var name = await PromptWindow.ShowAsync(this, "New folder", "Folder name:");
        if (!string.IsNullOrWhiteSpace(name))
            await vm.CreateFolderAsync(name.Trim());
    }
}
