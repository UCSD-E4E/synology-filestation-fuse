using SynologyFuse.Gui.Services;
using Xunit;

namespace SynologyFuse.Tests;

/// <summary>
/// Where the VPN profile is, and which of the two places is meant.
///
/// A profile has two: one on the NAS and one on this computer. The settings
/// screen showed a single field, so somebody asked for "the VPN profile"
/// reasonably typed the NAS path — and the connection failed trying to create
/// `/installers` on their own disk. They are asked separately now, and the
/// local one is only asked for when somebody already has the file.
/// </summary>
public class VpnProfileLocationTests
{
    [Fact]
    public void NoTunnelIsWantedWithoutSomewhereInsideItToGo()
    {
        // A profile alone cannot be used: the NAS answers at a private address
        // inside the tunnel, and nothing else knows what that is.
        Assert.Null(SettingsService.ResolveVpnProfile("/home/me/nas.ovpn", "/path/on/nas", ""));
        Assert.Null(SettingsService.ResolveVpnProfile(null, null, null));
    }

    [Fact]
    public void WithNoProfileInEitherPlaceThereIsNothingToUse()
    {
        // Wanting a tunnel is not the same as having what raises one. Returning
        // a path here would send the native side looking for a file that has
        // never existed, and report that as the tunnel failing.
        Assert.Null(SettingsService.ResolveVpnProfile("", "", "10.0.0.1"));
    }

    [Fact]
    public void AProfileOnTheNasIsDownloadedBesideTheSettings()
    {
        // The case somebody is in when they have never seen the file: they know
        // where the NAS publishes it and nothing else. Choosing the local
        // location for them is the point — being asked for it is what caused
        // the NAS's path to be typed into it.
        var resolved = SettingsService.ResolveVpnProfile("", "/shared/vpn.ovpn", "10.0.0.1");

        Assert.Equal(SettingsService.DefaultVpnProfilePath, resolved);
    }

    [Fact]
    public void AFileSomebodyAlreadyHasIsUsedInstead()
    {
        var resolved = SettingsService.ResolveVpnProfile("/home/me/mine.ovpn", "", "10.0.0.1");

        Assert.Equal("/home/me/mine.ovpn", resolved);
    }

    [Fact]
    public void TheirOwnFileWinsOverDownloadingAnother()
    {
        var resolved = SettingsService.ResolveVpnProfile(
            "/home/me/mine.ovpn", "/shared/vpn.ovpn", "10.0.0.1");

        Assert.Equal("/home/me/mine.ovpn", resolved);
    }
}
