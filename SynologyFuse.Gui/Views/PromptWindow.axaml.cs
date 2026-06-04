using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;

namespace SynologyFuse.Gui.Views;

/// <summary>Minimal modal text-input dialog. Returns the entered string, or
/// null if cancelled.</summary>
public partial class PromptWindow : Window
{
    public PromptWindow() => InitializeComponent();

    public static async Task<string?> ShowAsync(Window owner, string title, string label)
    {
        var dlg = new PromptWindow { Title = title };
        dlg.PromptLabel.Text = label;
        return await dlg.ShowDialog<string?>(owner);
    }

    private void OnOk(object? sender, RoutedEventArgs e) => Close(Input.Text);

    private void OnCancel(object? sender, RoutedEventArgs e) => Close(null);
}
