using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Headless;
using SynologyFuse.Tests;

[assembly: AvaloniaTestApplication(typeof(TestAppBuilder))]

namespace SynologyFuse.Tests;

/// <summary>
/// Headless Avalonia app for the layout tests. Drawing is the headless stub:
/// nothing is rasterised, only measured and arranged, so the tests need no
/// display, no Skia and no system fonts. Its font metrics are not the real
/// ones, which is the point — a layout that only holds for one font is the
/// bug these tests exist to catch.
/// </summary>
public static class TestAppBuilder
{
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<SynologyFuse.Gui.App>()
            .WithInterFont()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = true });

    /// <summary>Runs <paramref name="test"/> on the Avalonia UI thread of a
    /// headless session. Avalonia ships an xUnit adapter that does this with an
    /// attribute, but only for xUnit v3; this project is on v2, so the session
    /// is driven directly.</summary>
    public static Task RunOnUiThread(Action test) =>
        HeadlessUnitTestSession
            .GetOrStartForAssembly(Assembly.GetExecutingAssembly())
            .Dispatch(test, CancellationToken.None);
}
