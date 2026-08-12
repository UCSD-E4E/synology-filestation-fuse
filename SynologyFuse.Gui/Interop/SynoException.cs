using System;

namespace SynologyFuse.Gui.Interop;

/// <summary>
/// A typed error from the native FileStation client. Carries the
/// <see cref="Status"/> classification and, when applicable, the raw Synology
/// <see cref="DsmCode"/> so callers can react precisely instead of scraping
/// log text.
/// </summary>
public class SynoException : Exception
{
    internal SynoException(NativeMethods.SynoStatus status, uint dsmCode, string message)
        : base(message)
    {
        Status = status;
        DsmCode = dsmCode;
    }

    internal NativeMethods.SynoStatus Status { get; }

    /// <summary>Raw Synology DSM error code, or 0 when not applicable.</summary>
    public uint DsmCode { get; }
}

/// <summary>
/// Raised by <see cref="Services.SynoClient.Connect"/> when the account needs a
/// 2FA / OTP code. The GUI prompts for the code and retries the connect with it.
/// </summary>
public sealed class OtpRequiredException : SynoException
{
    internal OtpRequiredException(string message)
        : base(NativeMethods.SynoStatus.OtpRequired, 0, message)
    {
    }
}

/// <summary>
/// Raised when the NAS's TLS certificate could not be verified. Distinct from a
/// generic <see cref="SynoException"/> because it has a specific remedy: trust
/// the certificate, or tick "Accept self-signed certificate". A DSM appliance
/// ships self-signed, so this is the expected first-connect experience for many
/// users and the message needs to say what to do about it.
/// </summary>
public sealed class TlsVerificationException : SynoException
{
    internal TlsVerificationException(string message)
        : base(NativeMethods.SynoStatus.TlsError, 0, message)
    {
    }
}
