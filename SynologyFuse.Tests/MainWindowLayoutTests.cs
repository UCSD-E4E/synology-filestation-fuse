using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Presenters;
using System.Threading.Tasks;
using Avalonia.Threading;
using Avalonia.VisualTree;
using SynologyFuse.Gui.Views;
using Xunit;

namespace SynologyFuse.Tests;

/// <summary>
/// The main window is a column of label/field rows and a row of buttons, all
/// laid out by fixed-width <see cref="Grid"/> columns. Fixed widths hold only
/// while the text stays the size it was authored at: a wider system font, a
/// longer label, or a narrower window pushes a cell past its column, and
/// because a Grid does not clip, the overflow is *drawn on top of* the next
/// cell rather than being cut off. That is what "the UI is broken" looks like
/// — a label painted over its own help text, buttons stacked on each other,
/// the last button off the edge of the window.
///
/// These tests lay the real window out at the sizes it can actually be shown
/// at and assert the two things a form must never do: paint one cell over
/// another, or place a cell outside its container.
/// </summary>
public class MainWindowLayoutTests
{
    /// <summary>Sub-pixel rounding is not an overlap.</summary>
    private const double Epsilon = 0.5;

    [Theory]
    // The narrowest the window lets the user drag it, the width it opens at,
    // and the width it opens at under a larger system font — the case in the
    // bug report, where every label grew but its column did not.
    [InlineData(400.0, 14.0)]
    [InlineData(520.0, 14.0)]
    [InlineData(520.0, 17.0)]
    public Task NoCellIsPaintedOverAnother(double width, double fontSize) => TestAppBuilder.RunOnUiThread(() =>
    {
        var window = Show(width, fontSize);

        var problems = new List<string>();

        foreach (var grid in AuthoredGrids(window))
        {
            var cells = AuthoredChildren(grid);

            for (var i = 0; i < cells.Count; i++)
            {
                for (var j = i + 1; j < cells.Count; j++)
                {
                    if (Grid.GetColumn(cells[i]) == Grid.GetColumn(cells[j])) continue;

                    var a = Deflate(cells[i].Bounds);
                    var b = Deflate(cells[j].Bounds);
                    if (a.Intersects(b))
                        problems.Add($"{Describe(cells[i])} {a} overlaps {Describe(cells[j])} {b}");
                }
            }
        }

        Assert.True(problems.Count == 0,
            $"At {width}px wide with a {fontSize}pt font, cells overlap:\n  " +
            string.Join("\n  ", problems));
    });

    [Theory]
    [InlineData(400.0, 14.0)]
    [InlineData(520.0, 14.0)]
    [InlineData(520.0, 17.0)]
    public Task NoCellIsPlacedOutsideItsGrid(double width, double fontSize) => TestAppBuilder.RunOnUiThread(() =>
    {
        var window = Show(width, fontSize);

        var problems = new List<string>();

        foreach (var grid in AuthoredGrids(window))
        {
            foreach (var cell in AuthoredChildren(grid))
            {
                var right = cell.Bounds.Right + cell.Margin.Right;
                if (right > grid.Bounds.Width + Epsilon)
                    problems.Add(
                        $"{Describe(cell)} reaches {right:0.#}px, past the " +
                        $"{grid.Bounds.Width:0.#}px of its grid");
            }
        }

        Assert.True(problems.Count == 0,
            $"At {width}px wide with a {fontSize}pt font, cells escape their grid:\n  " +
            string.Join("\n  ", problems));
    });

    // ── helpers ───────────────────────────────────────────────────────────────

    private static Window Show(double width, double fontSize)
    {
        // No DataContext: the bindings go unset, which leaves every conditional
        // row visible. That is what we want — the rows a real connection hides
        // (the VPN address, the banners) still have to lay out when shown, and
        // the longest label in the window lives in one of them.
        var window = new MainWindow { Width = width, FontSize = fontSize };
        window.Show();
        Dispatcher.UIThread.RunJobs();
        return window;
    }

    /// <summary>Grids written in the XAML, not ones inside a control template —
    /// a template's internals are its own business and may legitimately share
    /// a cell.</summary>
    private static IEnumerable<Grid> AuthoredGrids(Window window) =>
        window.GetVisualDescendants()
              .OfType<Grid>()
              .Where(g => g.TemplatedParent is null && g.Bounds.Width > 0);

    private static List<Control> AuthoredChildren(Grid grid) =>
        grid.Children.OfType<Control>()
            .Where(c => c.IsVisible && c.Bounds.Width > 0 && c.Bounds.Height > 0)
            .ToList();

    /// <summary>Touching edges are not an overlap; only a real intrusion is.</summary>
    private static Rect Deflate(Rect r) =>
        new(r.X + Epsilon, r.Y + Epsilon,
            System.Math.Max(0, r.Width - 2 * Epsilon),
            System.Math.Max(0, r.Height - 2 * Epsilon));

    private static string Describe(Control c) => c switch
    {
        TextBlock t => $"TextBlock \"{Truncate(t.Text)}\"",
        TextBox t => $"TextBox \"{Truncate(t.PlaceholderText ?? t.Text)}\"",
        Button { Content: string s } => $"Button \"{s}\"",
        ContentPresenter p when p.Content is string s => $"ContentPresenter \"{s}\"",
        _ => c.GetType().Name,
    };

    private static string Truncate(string? s) =>
        s is null ? "" : s.Length <= 28 ? s : s[..28] + "…";
}
