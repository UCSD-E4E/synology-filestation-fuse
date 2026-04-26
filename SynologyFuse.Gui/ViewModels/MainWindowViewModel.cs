using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SynologyFuse.Gui.Models;
using SynologyFuse.Gui.Services;

namespace SynologyFuse.Gui.ViewModels;

public sealed partial class MainWindowViewModel : ObservableObject, IDisposable
{
    private readonly MountService _mountService = new();

    public MainWindowViewModel()
    {
        var s = SettingsService.Load();
        _host = s.Host;
        _username = s.Username;
        _port = s.Port;
        _useHttps = s.UseHttps;
        _mountpoint = s.Mountpoint;
        _cacheTtl = s.CacheTtl;
        _readCacheMb = s.ReadCacheMb;
        _logLevel = s.LogLevel;

        _ = CheckForUpdatesAsync();
    }

    private async Task CheckForUpdatesAsync()
    {
        var info = await UpdateCheckService.CheckAsync();
        if (info is null) return;

        Dispatcher.UIThread.Post(() =>
        {
            UpdateVersion = info.Latest.ToString();
            UpdateUrl = info.HtmlUrl;
            ShowUpdateBanner = true;
        });
    }

    // ── Connection fields ─────────────────────────────────────────────────────

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ConnectCommand))]
    private string _host;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ConnectCommand))]
    private string _username;

    [ObservableProperty]
    private string _password = "";

    [ObservableProperty]
    private decimal _port;

    [ObservableProperty]
    private bool _useHttps;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ConnectCommand))]
    private string _mountpoint;

    // ── Advanced ──────────────────────────────────────────────────────────────

    [ObservableProperty]
    private decimal _cacheTtl;

    [ObservableProperty]
    private decimal _readCacheMb;

    [ObservableProperty]
    private string _logLevel = "info"; // overwritten by constructor; default satisfies nullable analysis

    public IReadOnlyList<string> LogLevels { get; } =
        ["error", "warn", "info", "debug", "trace"];

    // ── State ─────────────────────────────────────────────────────────────────

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsDisconnected))]
    [NotifyCanExecuteChangedFor(nameof(ConnectCommand))]
    [NotifyCanExecuteChangedFor(nameof(DisconnectCommand))]
    private bool _isConnected;

    public bool IsDisconnected => !IsConnected;

    [ObservableProperty]
    private string _statusText = "Disconnected";

    [ObservableProperty]
    private string _logOutput = "";

    /// <summary>
    /// True when the CLI is blocked waiting for a 2FA code on stdin.
    /// Shows an inline banner so the user can type the code without restarting.
    /// </summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SubmitOtpCommand))]
    private bool _showOtpPrompt;

    /// <summary>The code the user typed in the 2FA banner.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SubmitOtpCommand))]
    private string _pendingOtp = "";

    // ── Update banner ─────────────────────────────────────────────────────────

    [ObservableProperty]
    private bool _showUpdateBanner;

    [ObservableProperty]
    private string _updateVersion = "";

    [ObservableProperty]
    private string _updateUrl = "";

    [RelayCommand]
    private void DismissUpdateBanner() => ShowUpdateBanner = false;

    [RelayCommand]
    private void OpenUpdateUrl()
    {
        if (string.IsNullOrEmpty(UpdateUrl)) return;
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = UpdateUrl,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            AppendLog($"Could not open browser: {ex.Message}");
        }
    }

    // ── Commands ──────────────────────────────────────────────────────────────

    [RelayCommand(CanExecute = nameof(CanConnect))]
    private async Task Connect()
    {
        ShowOtpPrompt = false;
        PendingOtp = "";
        AppendLog($"Connecting to {Host}…");
        StatusText = "Connecting…";

        SettingsService.Save(new PersistedSettings
        {
            Host = Host,
            Username = Username,
            Port = Port,
            UseHttps = UseHttps,
            Mountpoint = Mountpoint,
            CacheTtl = CacheTtl,
            ReadCacheMb = ReadCacheMb,
            LogLevel = LogLevel,
        });

        _mountService.OutputReceived += OnOutput;
        _mountService.PromptRequired += OnPromptRequired;
        _mountService.Exited += OnExited;

        try
        {
            var config = new MountConfig
            {
                Host = Host,
                Username = Username,
                Password = Password,
                Port = (ushort)Port,
                UseHttps = UseHttps,
                Mountpoint = Mountpoint,
                CacheTtl = (ulong)CacheTtl,
                ReadCacheMb = (ulong)ReadCacheMb,
                LogLevel = LogLevel,
            };

            await _mountService.StartAsync(config);

            if (_mountService.IsRunning)
            {
                IsConnected = true;
                StatusText = $"Mounted at {Mountpoint}";
                AppendLog("Mount process started.");
            }
            else
            {
                // Process already exited — OnExited has handled state.
                DetachEvents();
            }
        }
        catch (Exception ex)
        {
            AppendLog($"Error: {ex.Message}");
            StatusText = "Error";
            IsConnected = false;
            DetachEvents();
        }
    }

    private bool CanConnect() =>
        !IsConnected &&
        !string.IsNullOrWhiteSpace(Host) &&
        !string.IsNullOrWhiteSpace(Username) &&
        !string.IsNullOrWhiteSpace(Mountpoint);

    [RelayCommand(CanExecute = nameof(CanDisconnect))]
    private void Disconnect()
    {
        AppendLog("Disconnecting…");
        StatusText = "Disconnecting…";
        ShowOtpPrompt = false;
        _mountService.Stop();
        // IsConnected → false via OnExited.
    }

    private bool CanDisconnect() => IsConnected;

    /// <summary>
    /// Sends the user-entered OTP code to the waiting CLI process via stdin.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanSubmitOtp))]
    private void SubmitOtp()
    {
        var code = PendingOtp.Trim();
        AppendLog($"Sending 2FA code…");
        ShowOtpPrompt = false;
        PendingOtp = "";
        _mountService.SendLine(code);
        StatusText = "Verifying 2FA code…";
    }

    private bool CanSubmitOtp() =>
        ShowOtpPrompt && !string.IsNullOrWhiteSpace(PendingOtp);

    // ── Event handlers ────────────────────────────────────────────────────────

    private void OnOutput(string line) =>
        Dispatcher.UIThread.Post(() => AppendLog(line));

    private void OnPromptRequired(string prompt) =>
        Dispatcher.UIThread.Post(() =>
        {
            AppendLog($"[2FA] {prompt}");
            ShowOtpPrompt = true;
            StatusText = "2FA code required";
        });

    private void OnExited(int exitCode)
    {
        Dispatcher.UIThread.Post(() =>
        {
            DetachEvents();
            IsConnected = false;
            ShowOtpPrompt = false;
            StatusText = exitCode == 0 ? "Disconnected" : $"Exited (code {exitCode})";
            AppendLog($"Mount process exited with code {exitCode}.");
        });
    }

    private void DetachEvents()
    {
        _mountService.OutputReceived -= OnOutput;
        _mountService.PromptRequired -= OnPromptRequired;
        _mountService.Exited -= OnExited;
    }

    private void AppendLog(string line)
    {
        LogOutput = string.IsNullOrEmpty(LogOutput)
            ? line
            : LogOutput + Environment.NewLine + line;
    }

    public void Dispose() => _mountService.Dispose();
}
