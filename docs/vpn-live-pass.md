# Validating SMB over the OpenVPN tunnel

Everything this driver is being pointed at assumes one thing that has never
been observed: that an off-campus client can bring up the NAS's own OpenVPN
tunnel and mount SMB through it. The SMB backend has met mocks and a Docker
Samba container; it has not met DSM. Until this page has been walked through
once, treat the tunnel work as unvalidated.

It needs a human, off campus, with AD credentials. It is the last open item on
the server side too — `spec/e4e-nas/vpn.yml` in `KastnerRG/krg-infra` lists it
as bring-up step 7, the only one not yet done.

## What is already true

Steps 1–6 of that spec are applied: the VPN Server package is installed and
configured, local accounts are denied VPN access, and as of 2026-08-19 both
firewall rules are open, so `udp/1194` answers from the internet. The server is
OpenVPN 2.5.11 with `tls-auth` on, `AES-256-CBC` / `SHA512`, no compression,
and no DNS push. Clients get an address on `10.90.24.0/24` and can reach
exactly one thing: `10.90.24.1:445`.

## 1. Get the profile

`e4e-nas-vpn.ovpn` lives in the `installers` share, readable by any AD user.
It embeds `ta.key`, which makes it a shared secret — the thing that keeps
internet scanners off the daemon — so it is distributed through an
authenticated share and not a URL. Fetch it through DSM's web UI, which stays
reachable US-wide.

Keep it `0600`. Do not paste it into a terminal transcript, an issue, or a
chat log.

## 2. Bring the tunnel up

```bash
nix shell nixpkgs#openvpn -c sudo openvpn --config e4e-nas-vpn.ovpn
```

Two checkpoints, in order:

* **`TLS: Initial packet from …`** — this alone proves both that 1194 is open
  from where you are *and* that the HMAC gate accepted the published config,
  because a wrong or absent `ta.key` gets no reply at all rather than an error.
  It does not need credentials: failing afterwards at `AUTH_FAILED` is itself
  evidence that the auth path is enforcing.
* **`Initialization Sequence Completed`** — with real AD credentials.
  Authentication runs OpenVPN → radiusplugin → radiusd → `ntlm_auth` →
  winbind → the DC, entirely inside the NAS, so a DC outage looks like a
  password failure here.

Do not test with `ping`: ICMP is dropped by the `vpn` firewall adapter by
design. A silent `10.90.24.1` is expected and proves nothing either way.

## 3. Mount through it

```bash
synology-filestation-fuse \
  --host e4e-nas.ucsd.edu \
  --vpn-host 10.90.24.1 \
  --smb-domain KRG \
  --username <ad-user> \
  ~/mnt
```

`--host` is where FileStation is authenticated and where the fallback lives;
`--vpn-host` is where the NAS answers *inside* the tunnel. They differ because
the tunnel pushes no DNS. The mount logs which leg it chose — that line is the
result of this test.

Then copy a large file in. This is the first real exercise of three things that
have only ever run against a container: the replacing rename, `set_end_of_file`
truncation, and streamed write-through.

## 4. What to watch for

* **Kerberos → NTLMv2 fallback.** Clients cannot reach the DC through this
  tunnel, by design, so an SPN cannot be acquired and SMB falls back to NTLMv2,
  which the NAS pass-through-authenticates over its own network path. That has
  to work against `smb-globals.yml`'s `min_protocol SMB3` and server signing.
  Windows tries Kerberos first wherever it can resolve an SPN, so test a real
  Windows and a real macOS client before announcing the service, not just this
  driver.
* **Isolation.** A traceroute to anything else on campus must not go through
  the tunnel, and the DSM UI on `:6021` must not be reachable from inside it.
  If either is, `allow_lan` has been flipped and the NAS is routing onto the
  campus subnet.
* **Throughput and stalls.** `reneg-sec` defaults to an hour, so any copy that
  runs longer renegotiates mid-transfer. A copy that dies at roughly the
  one-hour mark is that, not the network.

## Why this gates the in-process client

`rust/synology-filestation-openvpn` exists to remove the `sudo openvpn` step
above — same tunnel, no tun device, no privileged helper, no effect on the
machine's other traffic. Every line of it is spent on the assumption that what
is on the far side is worth reaching. If SMB over this tunnel does not work
against real DSM, that is worth knowing before the protocol work, not after.
