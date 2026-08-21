using System;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SynologyFuse.Gui.Services;

namespace SynologyFuse.Gui.ViewModels;

/// <summary>
/// The error banner's state. A failure used to reach the user as the word
/// "Error" in the status bar plus a line in the log pane, which says nothing
/// about what to fix; this puts the cause and its remedy in front of them.
///
/// Deliberately separate from <see cref="MainWindowViewModel"/> so it holds no
/// native handles and can be exercised on its own.
/// </summary>
public sealed partial class ErrorBannerViewModel : ObservableObject
{
    [ObservableProperty]
    private bool _isVisible;

    /// <summary>Plain-language headline, e.g. "Wrong username or password".</summary>
    [ObservableProperty]
    private string _title = "";

    /// <summary>What the user should do about it.</summary>
    [ObservableProperty]
    private string _remedy = "";

    /// <summary>Raw native message and DSM code, for a bug report.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasDetail))]
    private string _detail = "";

    /// <summary>False when the failure carried no underlying message, so the
    /// banner can drop the detail line rather than show an empty one.</summary>
    public bool HasDetail => !string.IsNullOrWhiteSpace(Detail);

    /// <summary>Describe <paramref name="ex"/> and show the banner, replacing
    /// whatever it was showing before.</summary>
    public void Show(Exception ex)
    {
        var report = ErrorPresenter.Describe(ex);
        Title = report.Title;
        Remedy = report.Remedy;
        Detail = report.Detail;
        IsVisible = true;
    }

    /// <summary>Hide the banner — called when a new attempt starts, so a stale
    /// failure never sits next to a fresh success.</summary>
    public void Clear() => IsVisible = false;

    [RelayCommand]
    private void Dismiss() => Clear();
}
