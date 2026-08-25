using System;
using System.Threading.Tasks;
using SynologyFuse.Gui.Services;
using Xunit;

namespace SynologyFuse.Tests;

/// <summary>
/// A disconnect that does not finish must still say something.
///
/// Tearing a volume down unmounts it and then waits for the filesystem's own
/// workers to finish, which a read being retried against a NAS that has stopped
/// answering can hold open. Waiting on that with no bound is what left a window
/// showing a progress bar and the word "Working…" indefinitely — no error, no
/// end, and nothing to act on.
/// </summary>
public class DisconnectPatienceTests
{
    [Fact]
    public async Task WorkThatFinishesIsReportedAsFinished()
    {
        var done = await MountService.AwaitWithin(Task.CompletedTask, TimeSpan.FromSeconds(5));

        Assert.True(done);
    }

    [Fact]
    public async Task WorkThatDoesNotFinishIsGivenUpOnRatherThanWaitedFor()
    {
        // Never completes, as a teardown blocked in a native call does not.
        var stuck = new TaskCompletionSource().Task;

        var started = DateTime.UtcNow;
        var done = await MountService.AwaitWithin(stuck, TimeSpan.FromMilliseconds(200));

        Assert.False(done);
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(5),
            "it stopped waiting rather than waiting anyway");
    }

    [Fact]
    public async Task AFailureIsStillRaisedWhenItArrivesInTime()
    {
        // Not waiting forever must not turn into not noticing: a teardown that
        // fails quickly should still reach the error banner.
        var failing = Task.FromException(new InvalidOperationException("teardown went wrong"));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => MountService.AwaitWithin(failing, TimeSpan.FromSeconds(5)));
    }
}
