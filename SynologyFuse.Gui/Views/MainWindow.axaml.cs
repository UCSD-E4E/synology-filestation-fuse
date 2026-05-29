using Avalonia.Controls;
using Avalonia.Interactivity;
using SynologyFuse.Gui.ViewModels;

namespace SynologyFuse.Gui.Views;

public partial class MainWindow : Window
{
    public MainWindow() => InitializeComponent();

    private void OnBrowse(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not MainWindowViewModel vm) return;
        var browser = new FileBrowserWindow(vm.SnapshotConfig());
        browser.Show(this);
    }
}
