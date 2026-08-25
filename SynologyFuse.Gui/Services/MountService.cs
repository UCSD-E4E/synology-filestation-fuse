using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using SynologyFuse.Gui.Interop;
using SynologyFuse.Gui.Models;

namespace SynologyFuse.Gui.Services;

/// <summary>
/// Drives the native FileStation client directly (no subprocess). Connecting,
/// mounting and unmounting all run in-process via <see cref="SynoClient"/>.
/// Log lines from the native library are surfaced through
/// <see cref="OutputReceived"/>; connect/mount failures surface as
/// <see cref="SynoException"/> (or <see cref="OtpRequiredException"/> when a
/// 2FA code is needed).
/// </summary>
public sealed class MountService : IDisposable
{
    private SynoClient? _client;
    private bool _disposed;

    /// <summary>Raised for each log line emitted by the native library.
    /// May fire on a background thread — marshal to the UI thread in handlers.</summary>
    public event Action<string>? OutputReceived;

    public MountService()
    {
        // Route native log output to subscribers for the GUI log pane.
        SynoClient.SetLogCallback((_, line) => OutputReceived?.Invoke(line));
    }

    public bool IsMounted => _client is { IsMounted: true };

    /// <summary>Which leg the last connection reached the NAS by.
    ///
    /// <see cref="SynoTransport.Unknown"/> until something has connected. Worth
    /// showing: the difference between SMB and the HTTP API is the difference
    /// between a transfer that resumes where it stopped and one that starts
    /// again, and nothing else tells a user which they got.</summary>
    public SynoTransport Transport { get; private set; } = SynoTransport.Unknown;

    /// <summary>An empty setting means "not set", which the native side spells
    /// null. A blank string would be a domain of "" and a profile path of "".</summary>
    internal static string? Blank(string value) =>
        string.IsNullOrWhiteSpace(value) ? null : value;

    /// <summary>Where the profile lives on this computer for this connection:
    /// the file the user pointed at, or the copy a download is kept in.</summary>
    internal static string? VpnProfileFor(MountConfig config)
    {
        var resolved = SettingsService.ResolveVpnProfile(
            config.VpnProfile, config.VpnProfileNas, config.VpnHost);
        return resolved is null ? null : ExpandPath(resolved);
    }

    /// <summary>
    /// Connect and mount in one step. Throws <see cref="OtpRequiredException"/>
    /// when the account needs a 2FA code (prompt and retry with
    /// <paramref name="otp"/> set), or <see cref="SynoException"/> on failure.
    /// </summary>
    public async Task ConnectAndMountAsync(MountConfig config, string? otp = null)
    {
        if (_client is not null)
            throw new InvalidOperationException("Already mounted.");

        var mountpoint = ExpandPath(config.Mountpoint);
        SynoClient.SetLogLevel(config.LogLevel);

        var client = await Task.Run(() =>
        {
            var c = SynoClient.Connect(
                config.Host, config.Port, config.UseHttps, config.Username, config.Password, otp,
                autoRelogin: true, verifySsl: config.VerifySsl,
                smbDomain: Blank(config.SmbDomain),
                vpnProfile: VpnProfileFor(config),
                vpnHost: Blank(config.VpnHost),
                vpnProfileRemote: Blank(config.VpnProfileNas));
            try
            {
                c.Mount(mountpoint, config.CacheTtl, config.ReadCacheMb);
            }
            catch (SynoException ex)
            {
                c.Dispose();
                // The login already succeeded, so this is a mount-side failure —
                // retag it so the UI advises on the mount point instead of the
                // credentials.
                throw new MountFailedException(ex);
            }
            catch
            {
                c.Dispose();
                throw;
            }
            return c;
        });

        // If Dispose() ran (app shutdown) while connect+mount was in flight,
        // tear the freshly-built client down instead of leaking it. The await
        // resumed on the UI thread, so this can't race Dispose().
        if (_disposed)
        {
            client.Dispose();
            return;
        }
        _client = client;
        Transport = client.Transport;
    }

    /// <summary>
    /// Validate credentials by logging in and straight back out — no mount.
    /// Same exception contract as <see cref="ConnectAndMountAsync"/>.
    /// </summary>
    public Task TestConnectionAsync(MountConfig config, string? otp = null)
    {
        SynoClient.SetLogLevel(config.LogLevel);
        return Task.Run(() =>
        {
            using var client = SynoClient.Connect(
                config.Host, config.Port, config.UseHttps, config.Username, config.Password, otp,
                autoRelogin: true, verifySsl: config.VerifySsl,
                smbDomain: Blank(config.SmbDomain),
                vpnProfile: VpnProfileFor(config),
                vpnHost: Blank(config.VpnHost),
                vpnProfileRemote: Blank(config.VpnProfileNas));
            Transport = client.Transport;
            // Dispose logs out immediately; reaching here means success.
        });
    }

    /// <summary>Unmount and log out, if connected.</summary>
    public void Stop()
    {
        _client?.Dispose();
        _client = null;
    }

    /// <summary>How long a disconnect is worth waiting for before saying so.
    ///
    /// Teardown unmounts the volume and then waits for the filesystem's own
    /// workers to finish — a read being retried against a NAS that has stopped
    /// answering can hold that open for as long as the retries last. That is
    /// not a reason to leave somebody looking at a progress bar with no idea
    /// whether anything is happening.</summary>
    public static readonly TimeSpan StopPatience = TimeSpan.FromSeconds(20);

    /// <summary>Stop, and say whether it finished.
    ///
    /// False means teardown is still running: the volume is unmounted either
    /// way — that is the first thing it does — but the session is still being
    /// closed. It is deliberately not abandoned, because the native call owns
    /// the handle and cannot be interrupted from here; it is only stopped
    /// being waited on.</summary>
    public Task<bool> StopAsync() => AwaitWithin(Task.Run(Stop), StopPatience);

    /// <summary>Wait for <paramref name="work"/>, but not forever.
    ///
    /// Returns false if it is still running. The work is not cancelled — it
    /// owns a native handle and cannot be interrupted from here — it is only
    /// stopped being waited on, which is the difference between a window that
    /// says what happened and one that shows a progress bar indefinitely.
    ///
    /// Separated from <see cref="StopAsync"/> so the rule can be tested: this
    /// service's constructor talks to the native library, which a unit test
    /// has no business needing.</summary>
    internal static async Task<bool> AwaitWithin(Task work, TimeSpan patience)
    {
        var finished = await Task.WhenAny(work, Task.Delay(patience)) == work;
        // Only when it finished: awaiting the other branch would wait forever
        // for the thing we just decided not to wait for. A failure that
        // arrives later is unobserved, which is why `Stop` swallows nothing.
        if (finished) await work;
        return finished;
    }

    public void Dispose()
    {
        _disposed = true;
        Stop();
        SynoClient.SetLogCallback(null);
    }

    // ── Path expansion (shell-style conveniences the user expects) ──────────────

    internal static string ExpandPath(string path)
    {
        // Expand ~ to the user's home directory (a direct native call does not
        // get shell expansion).
        if (path == "~" || path.StartsWith("~/") || path.StartsWith(@"~\"))
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            path = home + path[1..];
        }

        return ExpandEnvVars(path);
    }

    private static readonly Regex EnvVarUnix =
        new(@"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)", RegexOptions.Compiled);

    internal static string ExpandEnvVars(string path)
    {
        // %VAR% — Windows style (also works on Linux in case someone types it).
        path = Environment.ExpandEnvironmentVariables(path);

        // $VAR / ${VAR} — Unix style (not handled by ExpandEnvironmentVariables on Windows).
        path = EnvVarUnix.Replace(path, m =>
        {
            var name = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
            return Environment.GetEnvironmentVariable(name) ?? m.Value;
        });

        return path;
    }
}
