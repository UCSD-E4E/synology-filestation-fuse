using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SynologyFuse.Gui.Interop;
using SynologyFuse.Gui.Models;
using SynologyFuse.Gui.Services;

namespace SynologyFuse.Gui.ViewModels;

/// <summary>
/// Backs the pre-mount file browser. Owns its own <see cref="SynoClient"/>
/// session (connect on open, dispose on close) and exercises the full client
/// surface: list shares/dirs, download, upload, delete, create folder. Browse
/// works without mounting anything.
/// </summary>
public sealed partial class FileBrowserViewModel : ObservableObject, IDisposable
{
    private readonly MountConfig _config;
    private SynoClient? _client;
    private bool _disposed;

    // Serializes every native call against Dispose() so the handle is never
    // freed while a P/Invoke is in flight. The gate is taken and released on
    // the worker thread inside Task.Run (never the UI thread), so Dispose() can
    // block on it without risking a deadlock.
    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <summary>Path stack for breadcrumb navigation; "" denotes the shares root.</summary>
    private readonly Stack<string> _history = new();

    public FileBrowserViewModel(MountConfig config) => _config = config;

    public ObservableCollection<SynoFileInfo> Items { get; } = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(UpCommand))]
    [NotifyCanExecuteChangedFor(nameof(RefreshCommand))]
    private string _currentPath = "";

    [ObservableProperty]
    private SynoFileInfo? _selectedItem;

    [ObservableProperty]
    private string _status = "Connecting…";

    [ObservableProperty]
    private bool _isBusy;

    // ── 2FA ─────────────────────────────────────────────────────────────────────

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SubmitOtpCommand))]
    private bool _showOtpPrompt;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SubmitOtpCommand))]
    private string _pendingOtp = "";

    // ── Transfer progress ─────────────────────────────────────────────────────

    [ObservableProperty]
    private bool _showProgress;

    [ObservableProperty]
    private double _progressValue;

    [ObservableProperty]
    private double _progressMax = 1;

    [ObservableProperty]
    private string _progressText = "";

    public bool IsConnected => _client is not null;

    // ── Connect ──────────────────────────────────────────────────────────────────

    /// <summary>Connect the browser's session. Call once when the window opens.</summary>
    public Task ConnectAsync() => ConnectAsync(null);

    private async Task ConnectAsync(string? otp)
    {
        IsBusy = true;
        Status = "Connecting…";
        try
        {
            var client = await Task.Run(() => SynoClient.Connect(
                _config.Host, _config.Port, _config.UseHttps, _config.Username, _config.Password, otp));
            // If the window was closed (Dispose ran) while the login was in
            // flight, the handle would otherwise leak — dispose it and bail.
            // The await resumed on the UI thread, so this can't race Dispose().
            if (_disposed)
            {
                client.Dispose();
                return;
            }
            _client = client;
            ShowOtpPrompt = false;
            OnPropertyChanged(nameof(IsConnected));
            await LoadAsync("");
        }
        catch (OtpRequiredException)
        {
            ShowOtpPrompt = true;
            Status = "2FA code required";
        }
        catch (Exception ex)
        {
            Status = $"Error: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanSubmitOtp))]
    private async Task SubmitOtp()
    {
        var code = PendingOtp.Trim();
        ShowOtpPrompt = false;
        PendingOtp = "";
        await ConnectAsync(code);
    }

    private bool CanSubmitOtp() => ShowOtpPrompt && !string.IsNullOrWhiteSpace(PendingOtp);

    // ── Navigation ───────────────────────────────────────────────────────────────

    private async Task LoadAsync(string path)
    {
        if (_client is null) return;
        IsBusy = true;
        Status = path.Length == 0 ? "Loading shares…" : $"Loading {path}…";
        try
        {
            var entries = await GatedAsync(c => path.Length == 0 ? c.ListShares() : c.ListDir(path));
            if (entries is null) return; // client was disposed mid-call

            Items.Clear();
            foreach (var e in entries) Items.Add(e);
            CurrentPath = path;
            SelectedItem = null;
            Status = $"{Items.Count} item(s)" + (path.Length == 0 ? " (shares)" : $" in {path}");
        }
        catch (Exception ex)
        {
            Status = $"Error: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
            RefreshCommand.NotifyCanExecuteChanged();
            UpCommand.NotifyCanExecuteChanged();
        }
    }

    /// <summary>Descend into the selected directory (no-op for files).</summary>
    [RelayCommand]
    private async Task Open()
    {
        if (SelectedItem is not { IsDir: true } dir) return;
        _history.Push(CurrentPath);
        await LoadAsync(dir.Path);
    }

    [RelayCommand(CanExecute = nameof(CanGoUp))]
    private async Task Up()
    {
        var target = _history.Count > 0 ? _history.Pop() : "";
        await LoadAsync(target);
    }

    private bool CanGoUp() => CurrentPath.Length != 0;

    [RelayCommand(CanExecute = nameof(CanRefresh))]
    private Task Refresh() => LoadAsync(CurrentPath);

    private bool CanRefresh() => IsConnected;

    // ── Operations (invoked by the view, which supplies file-picker paths) ──────

    public async Task DownloadAsync(SynoFileInfo item, string localPath)
    {
        if (_client is null || item.IsDir) return;
        await RunWithProgressAsync($"Downloading {item.Name}…", client =>
            client.DownloadTo(item.Path, localPath, ReportProgress));
    }

    public async Task UploadAsync(string localPath)
    {
        if (_client is null || CurrentPath.Length == 0) return; // can't upload to the shares root
        var name = System.IO.Path.GetFileName(localPath);
        await RunWithProgressAsync($"Uploading {name}…", client =>
            client.Upload(localPath, CurrentPath, overwrite: true, ReportProgress));
        await LoadAsync(CurrentPath);
    }

    [RelayCommand]
    private async Task Delete()
    {
        if (_client is null || SelectedItem is null) return;
        var item = SelectedItem;
        await RunWithProgressAsync($"Deleting {item.Name}…", client => client.Delete(item.Path));
        await LoadAsync(CurrentPath);
    }

    public async Task CreateFolderAsync(string name)
    {
        if (_client is null || CurrentPath.Length == 0 || string.IsNullOrWhiteSpace(name)) return;
        await RunWithProgressAsync($"Creating {name}…", client => client.CreateFolder(CurrentPath, name));
        await LoadAsync(CurrentPath);
    }

    private async Task RunWithProgressAsync(string status, Action<SynoClient> op)
    {
        if (_client is null) return;
        IsBusy = true;
        ShowProgress = true;
        ProgressValue = 0;
        ProgressMax = 1;
        ProgressText = status;
        Status = status;
        try
        {
            await GatedAsync(op);
            Status = "Done";
        }
        catch (Exception ex)
        {
            Status = $"Error: {ex.Message}";
        }
        finally
        {
            ShowProgress = false;
            IsBusy = false;
        }
    }

    /// <summary>Run a native call that returns a value under the gate, on a
    /// worker thread. Returns null if the client was disposed.</summary>
    private Task<T?> GatedAsync<T>(Func<SynoClient, T> op) where T : class =>
        Task.Run<T?>(() =>
        {
            _gate.Wait();
            try
            {
                var c = _client;
                return c is null ? null : op(c);
            }
            finally { _gate.Release(); }
        });

    /// <summary>Run a native call with no return value under the gate.</summary>
    private Task GatedAsync(Action<SynoClient> op) =>
        Task.Run(() =>
        {
            _gate.Wait();
            try
            {
                var c = _client;
                if (c is not null) op(c);
            }
            finally { _gate.Release(); }
        });

    // Marshals native-thread progress callbacks onto the UI thread.
    private void ReportProgress(long done, long total) =>
        Dispatcher.UIThread.Post(() =>
        {
            ProgressMax = total > 0 ? total : Math.Max(done, 1);
            ProgressValue = done;
            ProgressText = total > 0
                ? $"{Bytes(done)} / {Bytes(total)}"
                : Bytes(done);
        });

    private static string Bytes(long n)
    {
        string[] units = ["B", "KiB", "MiB", "GiB", "TiB"];
        double v = n;
        int u = 0;
        while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
        return $"{v:0.#} {units[u]}";
    }

    public void Dispose()
    {
        _disposed = true;
        // Block until any in-flight native op (which holds the gate on a worker
        // thread) finishes, so we never free the handle mid-P/Invoke. The gate
        // is released off the UI thread, so this Wait can't deadlock.
        _gate.Wait();
        try
        {
            _client?.Dispose();
            _client = null;
        }
        finally
        {
            _gate.Release();
        }
    }
}
