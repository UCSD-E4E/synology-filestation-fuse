using System;
using System.Linq;
using SynologyFuse.Gui.Services;
using Xunit;

namespace SynologyFuse.Tests;

/// <summary>
/// The log pane's contents, bounded.
///
/// The pane used to be one string the view model appended to per line —
/// reallocating the whole buffer, raising a change notification, and
/// re-rendering a TextBox bound to all of it, once per line, on the UI thread.
/// It was quadratic and unbounded, so a chatty moment (a VPN handshake at debug
/// level) stopped the window responding. A log that forgets its oldest lines is
/// strictly better than an application that stops.
/// </summary>
public class LogBufferTests
{
    [Fact]
    public void Append_BelowCapacity_KeepsEveryLineInOrder()
    {
        var log = new LogBuffer(capacity: 10);

        log.Append("first");
        log.Append("second");

        Assert.Equal($"first{Environment.NewLine}second", log.Text);
    }

    [Fact]
    public void Text_WhenEmpty_IsEmptyRatherThanABlankLine()
    {
        Assert.Equal("", new LogBuffer().Text);
    }

    /// <summary>
    /// The point of the whole class: past the cap, memory and per-flush work
    /// stop growing with how long the session has been running.
    /// </summary>
    [Fact]
    public void Append_PastCapacity_DropsTheOldestAndKeepsTheNewest()
    {
        var log = new LogBuffer(capacity: 3);

        foreach (var i in Enumerable.Range(1, 100)) log.Append($"line {i}");

        var lines = log.Text.Split(Environment.NewLine);
        Assert.Equal(new[] { "line 98", "line 99", "line 100" }, lines.TakeLast(3));
        Assert.DoesNotContain("line 97", log.Text);
    }

    /// <summary>
    /// Silently discarding is its own kind of lie: somebody reading the pane
    /// to diagnose a failure needs to know the top of it is missing, or they
    /// will conclude the run started where the buffer does.
    /// </summary>
    [Fact]
    public void Text_AfterDropping_SaysSoRatherThanPretendingToBeWhole()
    {
        var log = new LogBuffer(capacity: 2);

        log.Append("a");
        log.Append("b");
        Assert.DoesNotContain("older lines", log.Text);

        log.Append("c");

        Assert.StartsWith("…", log.Text);
        Assert.Contains("older lines", log.Text);
    }

    /// <summary>
    /// Lines arrive on whatever thread the native log callback runs on, which
    /// is not the UI thread and is not one thread.
    /// </summary>
    [Fact]
    public void Append_FromManyThreadsAtOnce_LosesNothingAndDoesNotTear()
    {
        var log = new LogBuffer(capacity: 10_000);

        System.Threading.Tasks.Parallel.For(0, 1_000, i => log.Append($"line {i}"));

        Assert.Equal(1_000, log.Text.Split(Environment.NewLine).Length);
    }

    /// <summary>A capacity of zero or less would make the pane useless, and is
    /// a caller's mistake rather than something to quietly honour.</summary>
    [Fact]
    public void Constructor_RejectsACapacityThatCouldHoldNothing()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new LogBuffer(capacity: 0));
    }
}
