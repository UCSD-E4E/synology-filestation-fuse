using System;
using SynologyFuse.Gui.Interop;
using SynologyFuse.Gui.ViewModels;
using Xunit;
using static SynologyFuse.Gui.Interop.NativeMethods;

namespace SynologyFuse.Tests;

/// <summary>
/// The banner's own state machine. Kept separate from
/// <see cref="MountServiceTests"/> so it exercises without a native client.
/// </summary>
public class ErrorBannerViewModelTests
{
    [Fact]
    public void Show_MakesTheBannerVisibleWithAdvice()
    {
        var vm = new ErrorBannerViewModel();

        vm.Show(new SynoException(SynoStatus.LoginFailed, 400, "invalid password"));

        Assert.True(vm.IsVisible);
        Assert.Contains("password", vm.Title, StringComparison.OrdinalIgnoreCase);
        Assert.False(string.IsNullOrWhiteSpace(vm.Remedy));
    }

    [Fact]
    public void Clear_HidesTheBanner()
    {
        var vm = new ErrorBannerViewModel();
        vm.Show(new InvalidOperationException("boom"));

        vm.Clear();

        Assert.False(vm.IsVisible);
    }

    [Fact]
    public void Dismiss_HidesTheBanner()
    {
        var vm = new ErrorBannerViewModel();
        vm.Show(new InvalidOperationException("boom"));

        vm.DismissCommand.Execute(null);

        Assert.False(vm.IsVisible);
    }

    [Fact]
    public void Show_ReplacesThePreviousError()
    {
        var vm = new ErrorBannerViewModel();
        vm.Show(new SynoException(SynoStatus.LoginFailed, 400, "invalid password"));

        vm.Show(new SynoException(SynoStatus.Io, 0, "connection refused"));

        Assert.Contains("connection refused", vm.Detail);
        Assert.DoesNotContain("invalid password", vm.Detail);
    }

    [Fact]
    public void HasDetail_FalseWhenTheErrorCarriesNoDetail()
    {
        var vm = new ErrorBannerViewModel();

        vm.Show(new SynoException(SynoStatus.Io, 0, ""));

        Assert.False(vm.HasDetail);
    }

    [Fact]
    public void HasDetail_TrueWhenThereIsSomethingToShow()
    {
        var vm = new ErrorBannerViewModel();

        vm.Show(new SynoException(SynoStatus.Io, 0, "connection refused"));

        Assert.True(vm.HasDetail);
    }
}
