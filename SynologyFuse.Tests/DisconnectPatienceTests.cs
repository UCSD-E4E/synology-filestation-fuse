using System;
using System.Threading.Tasks;
using SynologyFuse.Gui.Services;
using Xunit;

namespace SynologyFuse.Tests;

/// <summary>
/// A disconnect that is taking a while must say so — and must keep waiting.
///
/// Tearing a volume down unmounts it and then waits for the filesystem's own
/// workers to finish, which a read being retried against a NAS that has stopped
/// answering can hold open. Waiting silently is what left a window showing a
/// progress bar and the word "Working…" indefinitely.
///
/// Giving up on the wait, though, gives up on nothing: the work owns a native
/// handle and carries on regardless, while `Stop` has not yet reached the line
/// that releases the service's own reference. A window reporting "Disconnected"
/// there would re-enable Connect over a service that still holds a client, and
/// every later attempt would fail with "Already mounted." So the deadline
/// changes what is said, not what is true.
/// </summary>
public class DisconnectPatienceTests
{
    [Fact]
    public async Task WorkThatFinishesInTimeSaysNothing()
    {
        var reported = false;

        await MountService.NotifyIfSlow(
            Task.CompletedTask, TimeSpan.FromSeconds(5), () => reported = true);

        Assert.False(reported);
    }

    [Fact]
    public async Task WorkThatIsSlowIsReportedAndStillWaitedFor()
    {
        // The heart of it. The report fires at the deadline; the wait continues
        // to the end, so nothing acts on a teardown that has not finished.
        var slow = new TaskCompletionSource();
        var reported = new TaskCompletionSource();

        var waiting = MountService.NotifyIfSlow(
            slow.Task, TimeSpan.FromMilliseconds(100), () => reported.TrySetResult());

        await reported.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.False(waiting.IsCompleted, "reported, and still waiting");

        slow.SetResult();
        await waiting.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task AFailureIsStillRaised()
    {
        // Reporting slowness must not turn into swallowing errors: a teardown
        // that fails should still reach the error banner.
        var failing = Task.FromException(new InvalidOperationException("teardown went wrong"));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => MountService.NotifyIfSlow(failing, TimeSpan.FromSeconds(5), null));
    }
}
