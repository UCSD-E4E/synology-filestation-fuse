using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SynologyFuse.Gui.Interop;
using SynologyFuse.Gui.Models;
using SynologyFuse.Gui.Services;

namespace SynologyFuse.Gui.ViewModels;

public sealed partial class MainWindowViewModel : ObservableObject, IDisposable
{
    private readonly MountService _mountService = new();

    /// <summary>The action the OTP banner is gating: either a full mount or a
    /// connection test. Set when a connect attempt reports OTP-required so
    /// <see cref="SubmitOtp"/> knows which operation to retry.</summary>
    private enum PendingAction { None, Mount, Test }

    private PendingAction _pending = PendingAction.None;
    private MountConfig? _pendingConfig;

    public MainWindowViewModel()
    {
        var s = SettingsService.Load();
        _host = s.Host;
        _username = s.Username;
        _port = s.Port;
        _useHttps = s.UseHttps;
        _verifySsl = s.VerifySsl;
        _mountpoint = s.Mountpoint;
        _cacheTtl = s.CacheTtl;
        _readCacheMb = s.ReadCacheMb;
        _logLevel = s.LogLevel;
        _smbDomain = s.SmbDomain;
        _vpnProfile = s.VpnProfile;
        _vpnHost = s.VpnHost;

        _mountService.OutputReceived += OnOutput;

        var v = UpdateCheckService.CurrentVersion();
        Version = $"v{v.Major}.{v.Minor}.{v.Build}";

        _ = CheckForUpdatesAsync();
    }

    public string Version { get; }

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
    [NotifyCanExecuteChangedFor(nameof(TestConnectionCommand))]
    private string _host;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ConnectCommand))]
    [NotifyCanExecuteChangedFor(nameof(TestConnectionCommand))]
    private string _username;

    [ObservableProperty]
    private string _password = "";

    [ObservableProperty]
    private decimal _port;

    [ObservableProperty]
    private bool _useHttps;

    /// <summary>Verify the NAS TLS certificate. Unticking this accepts any
    /// certificate: encrypted, but not authenticated.</summary>
    [ObservableProperty]
    private bool _verifySsl = true;

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

    /// <summary>NetBIOS domain for SMB — `KRG` for an AD account, empty for a
    /// local DSM user. Empty against an AD account is why a connection ends up
    /// on the slower HTTP path without saying so.</summary>
    [ObservableProperty]
    private string _smbDomain = "";

    /// <summary>Where the OpenVPN profile is kept. With one, a NAS that does
    /// not answer directly is reached through a tunnel raised inside this
    /// process. Fetched from the NAS if the file is not there.</summary>
    [ObservableProperty]
    private string _vpnProfile = "";

    /// <summary>The NAS's address inside that tunnel, which its public name
    /// does not resolve to.</summary>
    [ObservableProperty]
    private string _vpnHost = "";

    public IReadOnlyList<string> LogLevels { get; } =
        ["error", "warn", "info", "debug", "trace"];

    // ── State ─────────────────────────────────────────────────────────────────

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsDisconnected))]
    [NotifyCanExecuteChangedFor(nameof(ConnectCommand))]
    [NotifyCanExecuteChangedFor(nameof(DisconnectCommand))]
    [NotifyCanExecuteChangedFor(nameof(TestConnectionCommand))]
    private bool _isConnected;

    public bool IsDisconnected => !IsConnected;

    /// <summary>True while a connect / test / mount attempt is in flight. Drives
    /// the spinner and disables the action buttons.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsIdle))]
    [NotifyCanExecuteChangedFor(nameof(ConnectCommand))]
    [NotifyCanExecuteChangedFor(nameof(TestConnectionCommand))]
    [NotifyCanExecuteChangedFor(nameof(DisconnectCommand))]
    private bool _isConnecting;

    public bool IsIdle => !IsConnecting;

    [ObservableProperty]
    private string _statusText = "Disconnected";

    /// <summary>Which leg the connection reached the NAS by.
    ///
    /// Shown as a badge, because the difference between these is the difference
    /// between a transfer that resumes where it stopped and one that starts
    /// again — and until now nothing told anyone which they had.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TransportBadge))]
    [NotifyPropertyChangedFor(nameof(TransportDetail))]
    [NotifyPropertyChangedFor(nameof(HasTransport))]
    private SynoTransport _transport = SynoTransport.Unknown;

    public bool HasTransport => Transport != SynoTransport.Unknown;

    public string TransportBadge => TransportPresenter.Badge(Transport);

    public string TransportDetail => TransportPresenter.Detail(Transport);

    [ObservableProperty]
    private string _logOutput = "";

    /// <summary>True when a 2FA code is required to finish connecting. Shows an
    /// inline banner so the user can supply the code and retry.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SubmitOtpCommand))]
    private bool _showOtpPrompt;

    /// <summary>The code the user typed in the 2FA banner.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SubmitOtpCommand))]
    private string _pendingOtp = "";

    // ── Error banner ──────────────────────────────────────────────────────────

    /// <summary>What went wrong and what to do about it. Filled in by any
    /// connect / mount / disconnect failure and cleared when the next attempt
    /// starts, so a stale failure never sits next to a fresh success.</summary>
    public ErrorBannerViewModel ErrorBanner { get; } = new();

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
        PersistSettings();
        _pendingConfig = BuildConfig();
        await RunConnectAsync(PendingAction.Mount, _pendingConfig, otp: null);
    }

    [RelayCommand(CanExecute = nameof(CanConnect))]
    private async Task TestConnection()
    {
        PersistSettings();
        _pendingConfig = BuildConfig();
        await RunConnectAsync(PendingAction.Test, _pendingConfig, otp: null);
    }

    /// <summary>Shared connect path for both Mount and Test. Handles the spinner,
    /// the OTP-required banner, and error reporting uniformly.</summary>
    private async Task RunConnectAsync(PendingAction action, MountConfig config, string? otp)
    {
        ShowOtpPrompt = false;
        ErrorBanner.Clear();
        IsConnecting = true;
        StatusText = action == PendingAction.Test ? "Testing connection…" : "Connecting…";
        AppendLog(action == PendingAction.Test
            ? $"Testing connection to {config.Host}…"
            : $"Connecting to {config.Host}…");

        try
        {
            if (action == PendingAction.Test)
            {
                await _mountService.TestConnectionAsync(config, otp);
                Transport = _mountService.Transport;
                StatusText = "Connection OK";
                AppendLog($"Connection succeeded, using {TransportBadge}.");
                _pending = PendingAction.None;
            }
            else
            {
                await _mountService.ConnectAndMountAsync(config, otp);
                Transport = _mountService.Transport;
                IsConnected = true;
                StatusText = $"Volume ready at {config.Mountpoint}";
                AppendLog($"Volume ready, using {TransportBadge}.");
                _pending = PendingAction.None;
            }
        }
        catch (OtpRequiredException)
        {
            // Not an error: stash the in-flight action and prompt for the code.
            _pending = action;
            ShowOtpPrompt = true;
            StatusText = "2FA code required";
            AppendLog("[2FA] Two-factor authentication code required.");
        }
        catch (Exception ex)
        {
            IsConnected = false;
            Report(ex);
        }
        finally
        {
            IsConnecting = false;
        }
    }

    private bool CanConnect() =>
        !IsConnected &&
        !IsConnecting &&
        !string.IsNullOrWhiteSpace(Host) &&
        !string.IsNullOrWhiteSpace(Username) &&
        !string.IsNullOrWhiteSpace(Mountpoint);

    [RelayCommand(CanExecute = nameof(CanDisconnect))]
    private async Task Disconnect()
    {
        AppendLog("Disconnecting…");
        StatusText = "Disconnecting…";
        ShowOtpPrompt = false;
        ErrorBanner.Clear();
        IsConnecting = true;
        try
        {
            // Stop() disposes the native client and blocks while unmounting and
            // joining the background worker — keep it off the UI thread.
            await Task.Run(() => _mountService.Stop());
            IsConnected = false;
            // Nothing is being reached any more, so the badge goes with it: a
            // "SMB" next to "Disconnected" is a guess about a connection that
            // no longer exists, and the next one may not get the same leg.
            Transport = SynoTransport.Unknown;
            StatusText = "Disconnected";
            AppendLog("Volume closed.");
        }
        catch (Exception ex)
        {
            Report(ex);
        }
        finally
        {
            IsConnecting = false;
        }
    }

    private bool CanDisconnect() => IsConnected && !IsConnecting;

    /// <summary>Retry the gated connect/test with the user-entered OTP code.</summary>
    [RelayCommand(CanExecute = nameof(CanSubmitOtp))]
    private async Task SubmitOtp()
    {
        var code = PendingOtp.Trim();
        var action = _pending;
        var config = _pendingConfig;
        ShowOtpPrompt = false;
        PendingOtp = "";
        AppendLog("Submitting 2FA code…");

        if (config is null || action == PendingAction.None) return;
        await RunConnectAsync(action, config, code);
    }

    private bool CanSubmitOtp() =>
        ShowOtpPrompt && !string.IsNullOrWhiteSpace(PendingOtp);

    // ── Helpers ─────────────────────────────────────────────────────────────────

    /// <summary>Snapshot of the current form as a <see cref="MountConfig"/>,
    /// used by the file browser window.</summary>
    public MountConfig SnapshotConfig() => BuildConfig();

    private MountConfig BuildConfig() => new()
    {
        Host = Host,
        Username = Username,
        Password = Password,
        Port = (ushort)Port,
        UseHttps = UseHttps,
        VerifySsl = VerifySsl,
        Mountpoint = Mountpoint,
        CacheTtl = (ulong)CacheTtl,
        ReadCacheMb = (ulong)ReadCacheMb,
        LogLevel = LogLevel,
        SmbDomain = SmbDomain,
        VpnProfile = VpnProfile,
        VpnHost = VpnHost,
    };

    private void PersistSettings() => SettingsService.Save(new PersistedSettings
    {
        Host = Host,
        Username = Username,
        Port = Port,
        UseHttps = UseHttps,
        VerifySsl = VerifySsl,
        Mountpoint = Mountpoint,
        CacheTtl = CacheTtl,
        ReadCacheMb = ReadCacheMb,
        LogLevel = LogLevel,
        SmbDomain = SmbDomain,
        VpnProfile = VpnProfile,
        VpnHost = VpnHost,
    });

    // ── Event handlers ────────────────────────────────────────────────────────

    private void OnOutput(string line) =>
        Dispatcher.UIThread.Post(() => AppendLog(line));

    /// <summary>Surface a failure everywhere it belongs: the banner carries the
    /// cause and the remedy, the status bar the headline, the log pane the raw
    /// message. Previously a failure was only ever the word "Error" plus a log
    /// line, which never said what to fix.</summary>
    private void Report(Exception ex)
    {
        ErrorBanner.Show(ex);
        StatusText = ErrorBanner.Title;
        AppendLog(ErrorBanner.HasDetail
            ? $"Error: {ErrorBanner.Title} — {ErrorBanner.Detail}"
            : $"Error: {ErrorBanner.Title}");
    }

    private void AppendLog(string line)
    {
        LogOutput = string.IsNullOrEmpty(LogOutput)
            ? line
            : LogOutput + Environment.NewLine + line;
    }

    public void Dispose()
    {
        _mountService.OutputReceived -= OnOutput;
        _mountService.Dispose();
    }
}
