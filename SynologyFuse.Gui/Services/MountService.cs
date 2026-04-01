using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using SynologyFuse.Gui.Models;

namespace SynologyFuse.Gui.Services;

public sealed class MountService : IDisposable
{
    private Process? _process;
    private CancellationTokenSource? _cts;

    public event Action<string>? OutputReceived;
    public event Action<int>? Exited;

    /// <summary>
    /// Raised when the CLI is blocking on an interactive prompt (e.g. the 2FA
    /// code prompt). The string is the prompt label the CLI printed.
    /// </summary>
    public event Action<string>? PromptRequired;

    /// <summary>
    /// Starts the CLI process with the given config.
    /// Throws <see cref="FileNotFoundException"/> if the binary cannot be located.
    /// </summary>
    public async Task StartAsync(MountConfig config)
    {
        if (_process is not null)
            throw new InvalidOperationException("Already mounted.");

        var binaryPath = FindBinary();

        var args = BuildArgs(config);

        var psi = new ProcessStartInfo(binaryPath)
        {
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        // Pass credentials via environment variables to avoid exposure in process list.
        psi.Environment["SYNO_PASSWORD"] = config.Password;
        if (!string.IsNullOrEmpty(config.Otp))
            psi.Environment["SYNO_OTP"] = config.Otp;

        _cts = new CancellationTokenSource();
        _process = new Process { StartInfo = psi, EnableRaisingEvents = true };

        _process.OutputDataReceived += (_, e) =>
        {
            if (e.Data is not null) OutputReceived?.Invoke(StripAnsi(e.Data));
        };
        _process.Exited += (_, _) =>
        {
            var code = _process.ExitCode;
            Exited?.Invoke(code);
            Cleanup();
        };

        _process.Start();
        _process.BeginOutputReadLine();

        // stderr must be read manually rather than via BeginErrorReadLine because
        // the CLI's 2FA prompt uses eprint! (no trailing newline). BeginErrorReadLine
        // only fires on '\n', so the prompt would never be seen and the process
        // would hang forever waiting for stdin.
        _ = ReadStderrAsync(_process, _cts.Token);

        // Give the process a moment to fail fast (e.g. bad host).
        await Task.Delay(500, _cts.Token).ContinueWith(_ => { });
    }

    public void Stop()
    {
        if (_process is null || _process.HasExited) return;

        try
        {
            // On Unix, send SIGINT so the CLI can logout gracefully.
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                _process.Kill(entireProcessTree: false);
            else
                _process.Kill();
        }
        catch (InvalidOperationException) { }
    }

    public bool IsRunning => _process is { HasExited: false };

    /// <summary>
    /// Writes a line to the CLI's stdin (used to answer interactive prompts
    /// such as the 2FA code request).
    /// </summary>
    public void SendLine(string value)
    {
        if (_process is null || _process.HasExited) return;
        _process.StandardInput.WriteLine(value);
        _process.StandardInput.Flush();
    }

    // Reads stderr character-by-character so we can detect prompts that have no
    // trailing newline (e.g. "Two-factor authentication code: ").
    private async Task ReadStderrAsync(Process process, CancellationToken ct)
    {
        var reader = process.StandardError;
        var buf = new char[256];
        var line = new System.Text.StringBuilder();

        try
        {
            while (true)
            {
                var read = await reader.ReadAsync(buf, ct);
                if (read == 0) break; // EOF

                line.Append(buf, 0, read);

                // Flush any complete lines first.
                FlushLines(line);

                // After flushing complete lines, check if the remainder is a known prompt.
                var pending = line.ToString();
                if (pending.Contains("Two-factor authentication code", StringComparison.OrdinalIgnoreCase))
                {
                    PromptRequired?.Invoke("Two-factor authentication code");
                    line.Clear();
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception) { }

        // Emit any trailing partial line (e.g. a final error message without newline).
        var remaining = StripAnsi(line.ToString()).Trim();
        if (remaining.Length > 0)
            OutputReceived?.Invoke(remaining);
    }

    private void FlushLines(System.Text.StringBuilder sb)
    {
        while (true)
        {
            var text = sb.ToString();
            var nl = text.IndexOf('\n');
            if (nl < 0) break;

            var completeLine = text[..nl].TrimEnd('\r');
            sb.Remove(0, nl + 1);

            var stripped = StripAnsi(completeLine);
            if (stripped.Length > 0)
                OutputReceived?.Invoke(stripped);
        }
    }

    private void Cleanup()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
        _process?.Dispose();
        _process = null;
    }

    public void Dispose()
    {
        Stop();
        Cleanup();
    }

    // -------------------------------------------------------------------------

    private static string FindBinary()
    {
        var binaryName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? "synology-filestation-fuse.exe"
            : "synology-filestation-fuse";

        // 1. Beside the GUI executable (deployed layout).
        var exeDir = Path.GetDirectoryName(Environment.ProcessPath) ?? ".";
        var candidate1 = Path.Combine(exeDir, binaryName);
        if (File.Exists(candidate1)) return candidate1;

        // 2. Development layout: repo root / target / release.
        // GUI is at <repo>/SynologyFuse.Gui/bin/...
        var repoRoot = FindRepoRoot(exeDir);
        if (repoRoot is not null)
        {
            var candidate2 = Path.Combine(repoRoot, "target", "release", binaryName);
            if (File.Exists(candidate2)) return candidate2;

            var candidate3 = Path.Combine(repoRoot, "target", "debug", binaryName);
            if (File.Exists(candidate3)) return candidate3;
        }

        // 3. PATH fallback.
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
        {
            var candidate4 = Path.Combine(dir, binaryName);
            if (File.Exists(candidate4)) return candidate4;
        }

        throw new FileNotFoundException(
            $"Could not locate '{binaryName}'. " +
            "Build the Rust CLI with 'cargo build --release' and place it beside the GUI, " +
            "or add it to PATH.");
    }

    private static string? FindRepoRoot(string startDir)
    {
        var dir = new DirectoryInfo(startDir);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Cargo.toml")))
                return dir.FullName;
            dir = dir.Parent;
        }
        return null;
    }

    private static string BuildArgs(MountConfig config)
    {
        var parts = new List<string>
        {
            "--host", Quote(config.Host),
            "--username", Quote(config.Username),
            "--port", config.Port.ToString(),
            "--log-level", config.LogLevel,
        };

        if (!config.UseHttps)
            parts.AddRange(["--https", "false"]);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            parts.AddRange(["--cache-ttl", config.CacheTtl.ToString()]);
            parts.AddRange(["--read-cache-mb", config.ReadCacheMb.ToString()]);
        }

        parts.Add(Quote(ExpandPath(config.Mountpoint)));

        return string.Join(" ", parts);
    }

    private static string ExpandPath(string path)
    {
        // Expand ~ to the user's home directory (shells do this, direct process spawn doesn't).
        if (path == "~" || path.StartsWith("~/") || path.StartsWith(@"~\"))
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            path = home + path[1..];
        }

        // Expand environment variables: $VAR / ${VAR} on Unix, %VAR% on Windows.
        path = ExpandEnvVars(path);

        return path;
    }

    private static readonly Regex EnvVarUnix =
        new(@"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)", RegexOptions.Compiled);

    private static string ExpandEnvVars(string path)
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

    private static string Quote(string s) =>
        s.Contains(' ') ? $"\"{s}\"" : s;

    // Matches ESC [ ... <letter>  (CSI sequences, covers colors, dim, bold, etc.)
    // and bare ESC <char> (Fe sequences like ESC M).
    private static readonly Regex AnsiEscapeRegex =
        new(@"\x1b(\[[0-9;]*[A-Za-z]|.)", RegexOptions.Compiled);

    private static string StripAnsi(string s) => AnsiEscapeRegex.Replace(s, "");
}
