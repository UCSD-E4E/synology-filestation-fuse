# Changelog

## [0.3.0](https://github.com/UCSD-E4E/synology-filestation/compare/synology-filestation-gui-v0.2.1...synology-filestation-gui-v0.3.0) (2026-08-12)


### ⚠ BREAKING CHANGES

* TLS certificate verification is now on by default. A stock DSM appliance presents a self-signed certificate and will be rejected until it is trusted or verification is explicitly turned off.

### Features

* **core:** stream large uploads in slices instead of buffering whole files ([e8cce35](https://github.com/UCSD-E4E/synology-filestation/commit/e8cce358a289aab34efe5d71938b6927ae7253ef))
* **fuse:** add --password-stdin, and warn when the password comes from argv ([6193e2b](https://github.com/UCSD-E4E/synology-filestation/commit/6193e2b2cf80fad425705e6cfc2e2405ddb2f6d1))
* verify TLS certificates by default, and keep credentials out of the URL ([6594fda](https://github.com/UCSD-E4E/synology-filestation/commit/6594fdab53978d6f2e3de454d05aa338a848b917))


### Bug Fixes

* stop leaking the session id and passwords into logs ([1ad289a](https://github.com/UCSD-E4E/synology-filestation/commit/1ad289a27a7df52121e59b57c72d67c47dd66a3c))

## [0.2.1](https://github.com/UCSD-E4E/synology-filestation/compare/synology-filestation-gui-v0.2.0...synology-filestation-gui-v0.2.1) (2026-07-30)


### Features

* **gui:** copy NAS paths from the browser path bar and context menu ([dd63bd6](https://github.com/UCSD-E4E/synology-filestation/commit/dd63bd677af11bb1b8b7ba392a20f6fa80410c15))
* **gui:** copy NAS paths from the browser path bar and context menu ([f718536](https://github.com/UCSD-E4E/synology-filestation/commit/f7185360fdc037b292b99f5cc3c2459534fbbe7b))
