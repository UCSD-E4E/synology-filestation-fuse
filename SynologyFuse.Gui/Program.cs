using Avalonia;
using System;
using System.IO;

namespace SynologyFuse.Gui;

class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        try
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception ex)
        {
            var logPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SynologyFuse", "crash.log");
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);
                File.WriteAllText(logPath, $"{DateTime.Now:O}\n{ex}");
            }
            catch { }
            throw;
        }
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            // Prefer the native Wayland backend over XWayland when a usable
            // compositor is present: XWayland hands us a bitmap-scaled window
            // on HiDPI and fractional-scale displays, where Wayland renders at
            // the real scale factor. No-op on X11, macOS and Windows.
            .UseWaylandWithFallback()
            .WithInterFont()
            .LogToTrace();
}
