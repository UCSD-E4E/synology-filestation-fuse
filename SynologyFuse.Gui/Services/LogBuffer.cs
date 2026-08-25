using System;
using System.Collections.Generic;
using System.Text;

namespace SynologyFuse.Gui.Services;

/// <summary>
/// The log pane's contents: the most recent lines, and no more than that.
///
/// The pane used to be a single string the view model appended to, once per
/// line, on the UI thread — reallocating the whole buffer, raising a change
/// notification and re-rendering a TextBox bound to all of it, per line. That
/// is quadratic in the length of the session and unbounded in memory, so a
/// chatty moment (a VPN handshake with the log level turned up) stopped the
/// window responding altogether.
///
/// Holding a bounded number of lines makes the cost of rendering the pane a
/// function of the cap rather than of how long the session has been running. A
/// log that forgets its oldest lines is strictly better than an application
/// that stops, and <see cref="Text"/> says when it has forgotten some so
/// nobody reads a truncated pane as a whole one.
///
/// Every member is safe to call from any thread: lines arrive on whichever
/// thread the native log callback runs on, which is neither the UI thread nor
/// reliably one thread.
/// </summary>
public sealed class LogBuffer
{
    /// <summary>Lines kept. Enough to cover a connect, a mount and a failure
    /// with room to spare, and small enough that rendering it is cheap.</summary>
    public const int DefaultCapacity = 2_000;

    private readonly int _capacity;
    private readonly Queue<string> _lines = new();
    private readonly object _gate = new();
    private bool _dropped;

    public LogBuffer(int capacity = DefaultCapacity)
    {
        if (capacity < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(capacity), capacity, "a log pane that holds nothing is not a log pane");
        }

        _capacity = capacity;
    }

    /// <summary>Add a line, discarding the oldest if the buffer is full.</summary>
    public void Append(string line)
    {
        lock (_gate)
        {
            _lines.Enqueue(line);
            while (_lines.Count > _capacity)
            {
                _lines.Dequeue();
                _dropped = true;
            }
        }
    }

    /// <summary>Everything the pane should show, oldest first.</summary>
    public string Text
    {
        get
        {
            lock (_gate)
            {
                if (_lines.Count == 0) return "";

                var text = new StringBuilder();
                if (_dropped)
                {
                    // Said out loud: somebody reading this to diagnose a
                    // failure would otherwise conclude the run began where the
                    // buffer does.
                    text.Append("… older lines dropped …").Append(Environment.NewLine);
                }

                var first = true;
                foreach (var line in _lines)
                {
                    if (!first) text.Append(Environment.NewLine);
                    text.Append(line);
                    first = false;
                }

                return text.ToString();
            }
        }
    }
}
