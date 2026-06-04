using System;
using System.Runtime.InteropServices;
using System.Text.Json;
using SynologyFuse.Gui.Interop;
using SynologyFuse.Gui.Models;
using static SynologyFuse.Gui.Interop.NativeMethods;

namespace SynologyFuse.Gui.Services;

/// <summary>
/// Managed wrapper over the native FileStation client. Owns the opaque native
/// client handle and (once mounted) the mount handle, translating native
/// status codes into <see cref="SynoException"/>s and JSON payloads into
/// <see cref="SynoFileInfo"/>s.
///
/// All calls block on the native Tokio runtime; callers should invoke browse /
/// transfer methods off the UI thread.
/// </summary>
public sealed class SynoClient : IDisposable
{
    private IntPtr _client;
    private IntPtr _mount;
    private bool _disposed;

    static SynoClient() => NativeMethods.EnsureResolver();

    private SynoClient(IntPtr client) => _client = client;

    /// <summary>True once <see cref="Mount"/> has succeeded and not been undone.</summary>
    public bool IsMounted => _mount != IntPtr.Zero;

    // ── Connect ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Log in and return a connected client. Throws
    /// <see cref="OtpRequiredException"/> when the account needs a 2FA code (the
    /// caller should prompt and retry with <paramref name="otp"/> set), or
    /// <see cref="SynoException"/> on any other failure.
    /// </summary>
    public static SynoClient Connect(
        string host, ushort port, bool https, string username, string password,
        string? otp = null, bool autoRelogin = true)
    {
        NativeMethods.EnsureResolver();
        var err = default(NativeError);
        int rc = syno_connect(host, port, https, username, password, otp, autoRelogin,
            out var handle, ref err);
        Check(rc, ref err);
        return new SynoClient(handle);
    }

    // ── Browse ─────────────────────────────────────────────────────────────────

    public SynoFileInfo[] ListShares()
    {
        var err = default(NativeError);
        int rc = syno_list_shares(_client, out var json, ref err);
        Check(rc, ref err);
        return ParseArray(json);
    }

    public SynoFileInfo[] ListDir(string path)
    {
        var err = default(NativeError);
        int rc = syno_list_dir(_client, path, out var json, ref err);
        Check(rc, ref err);
        return ParseArray(json);
    }

    public SynoFileInfo GetInfo(string path)
    {
        var err = default(NativeError);
        int rc = syno_get_info(_client, path, out var json, ref err);
        Check(rc, ref err);
        return ParseObject(json);
    }

    // ── Transfers ──────────────────────────────────────────────────────────────

    /// <summary>Download <paramref name="remote"/> to <paramref name="local"/>,
    /// reporting (bytesDone, bytesTotal) via <paramref name="progress"/>.</summary>
    public void DownloadTo(string remote, string local, Action<long, long>? progress = null)
    {
        var err = default(NativeError);
        var (fp, keepAlive) = MakeProgress(progress);
        int rc = syno_download_to(_client, remote, local, fp, IntPtr.Zero, ref err);
        GC.KeepAlive(keepAlive);
        Check(rc, ref err);
    }

    /// <summary>Upload <paramref name="local"/> into the remote directory
    /// <paramref name="remoteDir"/>. Progress is coarse (0 → total).</summary>
    public void Upload(string local, string remoteDir, bool overwrite = true,
        Action<long, long>? progress = null)
    {
        var err = default(NativeError);
        var (fp, keepAlive) = MakeProgress(progress);
        int rc = syno_upload(_client, local, remoteDir, overwrite, fp, IntPtr.Zero, ref err);
        GC.KeepAlive(keepAlive);
        Check(rc, ref err);
    }

    public void Delete(string path)
    {
        var err = default(NativeError);
        Check(syno_delete(_client, path, ref err), ref err);
    }

    public void CreateFolder(string parent, string name)
    {
        var err = default(NativeError);
        Check(syno_create_folder(_client, parent, name, ref err), ref err);
    }

    public void Rename(string path, string newName)
    {
        var err = default(NativeError);
        Check(syno_rename(_client, path, newName, ref err), ref err);
    }

    // ── Mount lifecycle ──────────────────────────────────────────────────────────

    /// <summary>Mount the share at <paramref name="mountpoint"/> in-process.
    /// Returns once the mount is established (or throws on failure).</summary>
    public void Mount(string mountpoint, ulong cacheTtl, ulong readCacheMb)
    {
        var err = default(NativeError);
        int rc = syno_mount(_client, mountpoint, cacheTtl, readCacheMb, out var mount, ref err);
        Check(rc, ref err);
        _mount = mount;
    }

    /// <summary>Unmount, if mounted. Blocks until the background worker exits.</summary>
    public void Unmount()
    {
        if (_mount != IntPtr.Zero)
        {
            syno_unmount(_mount);
            _mount = IntPtr.Zero;
        }
    }

    // ── Logging bridge ───────────────────────────────────────────────────────────

    // Held to keep the delegate alive for as long as native code may call it.
    private static LogCb? _logKeepAlive;

    /// <summary>Route the library's log lines to <paramref name="onLine"/>
    /// (level, text), or pass null to clear. Installed process-wide.</summary>
    public static void SetLogCallback(Action<int, string>? onLine)
    {
        NativeMethods.EnsureResolver();
        if (onLine is null)
        {
            _logKeepAlive = null;
            syno_set_log_callback(IntPtr.Zero, IntPtr.Zero);
            return;
        }
        _logKeepAlive = (level, line, _) =>
        {
            // This runs as an unmanaged callback — an exception escaping here
            // would tear down the process. Swallow anything a subscriber throws.
            try
            {
                var text = line != IntPtr.Zero ? Marshal.PtrToStringUTF8(line) ?? "" : "";
                onLine(level, text);
            }
            catch
            {
                // Best-effort logging: never let a log line crash the app.
            }
        };
        syno_set_log_callback(Marshal.GetFunctionPointerForDelegate(_logKeepAlive), IntPtr.Zero);
    }

    // ── Dispose ────────────────────────────────────────────────────────────────

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Unmount();
        if (_client != IntPtr.Zero)
        {
            syno_logout(_client);
            syno_client_free(_client);
            _client = IntPtr.Zero;
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    private static (IntPtr fp, ProgressCb? keepAlive) MakeProgress(Action<long, long>? progress)
    {
        if (progress is null) return (IntPtr.Zero, null);
        // Invoked as an unmanaged callback — guard so a throwing progress
        // handler can't escape the native boundary and crash the process.
        ProgressCb cb = (done, total, _) =>
        {
            try { progress((long)done, (long)total); }
            catch { /* progress is advisory; never let it abort the transfer */ }
        };
        return (Marshal.GetFunctionPointerForDelegate(cb), cb);
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private static SynoFileInfo[] ParseArray(IntPtr json)
    {
        var s = TakeString(json);
        return JsonSerializer.Deserialize<SynoFileInfo[]>(s, JsonOpts) ?? Array.Empty<SynoFileInfo>();
    }

    private static SynoFileInfo ParseObject(IntPtr json)
    {
        var s = TakeString(json);
        return JsonSerializer.Deserialize<SynoFileInfo>(s, JsonOpts) ?? new SynoFileInfo();
    }

    /// <summary>Copy a native string to managed and free the native buffer.</summary>
    private static string TakeString(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero) return "";
        var s = Marshal.PtrToStringUTF8(ptr) ?? "";
        syno_string_free(ptr);
        return s;
    }

    /// <summary>Throw a typed exception for any non-OK status, freeing the
    /// native error message first.</summary>
    private static void Check(int rc, ref NativeError err)
    {
        var status = (SynoStatus)rc;
        if (status == SynoStatus.Ok) return;

        var message = err.Message != IntPtr.Zero ? Marshal.PtrToStringUTF8(err.Message) ?? "" : "";
        var dsm = err.DsmCode;
        if (err.Message != IntPtr.Zero)
        {
            syno_string_free(err.Message);
            err.Message = IntPtr.Zero;
        }
        if (message.Length == 0) message = $"native error {rc}";

        throw status == SynoStatus.OtpRequired
            ? new OtpRequiredException(message)
            : new SynoException(status, dsm, message);
    }
}
