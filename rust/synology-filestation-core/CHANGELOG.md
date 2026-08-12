# Changelog

## [0.3.1](https://github.com/UCSD-E4E/synology-filestation/compare/synology-filestation-core-v0.3.0...synology-filestation-core-v0.3.1) (2026-08-12)


### Bug Fixes

* **core:** stop the read timeout from killing large uploads ([da35f24](https://github.com/UCSD-E4E/synology-filestation/commit/da35f24c0475760e1612f6d11b2a2b5ffd4042db))
* **core:** stop the read timeout from killing large uploads ([fd8c4ab](https://github.com/UCSD-E4E/synology-filestation/commit/fd8c4ab6d16d15ee72c2fe4a5c2ddb173270505d))
* **core:** tighten upload verification after review ([2750f15](https://github.com/UCSD-E4E/synology-filestation/commit/2750f15d30668a16ae1df9b60d3041cd93a25a3a))

## [0.3.0](https://github.com/UCSD-E4E/synology-filestation/compare/synology-filestation-core-v0.2.1...synology-filestation-core-v0.3.0) (2026-08-12)


### ⚠ BREAKING CHANGES

* TLS certificate verification is now on by default. A stock DSM appliance presents a self-signed certificate and will be rejected until it is trusted or verification is explicitly turned off.

### Features

* **core:** stream large uploads in slices instead of buffering whole files ([0220d73](https://github.com/UCSD-E4E/synology-filestation/commit/0220d735ee1a6d95076e25aaa36a626c4ea0550b))
* **core:** stream large uploads in slices instead of buffering whole files ([e8cce35](https://github.com/UCSD-E4E/synology-filestation/commit/e8cce358a289aab34efe5d71938b6927ae7253ef))
* verify TLS certificates by default, and keep credentials out of the URL ([6594fda](https://github.com/UCSD-E4E/synology-filestation/commit/6594fdab53978d6f2e3de454d05aa338a848b917))


### Bug Fixes

* address review feedback on the slice-upload path ([f525881](https://github.com/UCSD-E4E/synology-filestation/commit/f525881b49e146f5413c655c50f68d39e2ba6e78))
* **core:** carry the session id in a cookie instead of the request URL ([740e8ff](https://github.com/UCSD-E4E/synology-filestation/commit/740e8ff59c4490627912944cebb3e6f868571ee0))
* **core:** fetch whole listings and re-clear before each upload retry ([8d6f3e7](https://github.com/UCSD-E4E/synology-filestation/commit/8d6f3e7ecc4940de16ab91d38c9813e75f7d134c))
* **core:** preserve the underlying cause of a transport error ([0290c91](https://github.com/UCSD-E4E/synology-filestation/commit/0290c91ca18679dcd42f9f9580d26b1ea75011f4))
* **core:** scrub secrets from error messages and logs ([f25012c](https://github.com/UCSD-E4E/synology-filestation/commit/f25012cfa02b09c19e08023635f3cfc5b962cc05))
* seven data-loss and corruption defects found in review (tier 1) ([6b044aa](https://github.com/UCSD-E4E/synology-filestation/commit/6b044aad69c4ed0f4ab84807ec6a1cc5ab8cc7ae))
* stop leaking the session id and passwords into logs ([1ad289a](https://github.com/UCSD-E4E/synology-filestation/commit/1ad289a27a7df52121e59b57c72d67c47dd66a3c))

## [0.2.1](https://github.com/UCSD-E4E/synology-filestation/compare/synology-filestation-core-v0.2.0...synology-filestation-core-v0.2.1) (2026-07-30)


### Miscellaneous Chores

* **synology-filestation-core:** Synchronize synology-filestation versions

## [0.2.0](https://github.com/UCSD-E4E/synology-filestation/compare/synology-filestation-core-v0.1.20...synology-filestation-core-v0.2.0) (2026-07-29)


### Features

* streaming reads — fetch large files straight to disk (+ auto_attach) ([6f7d473](https://github.com/UCSD-E4E/synology-filestation/commit/6f7d473085c73fdfe98ea17c29f4418f3e9544ad))
* streaming reads (fetch large files straight to disk) ([7bd32f3](https://github.com/UCSD-E4E/synology-filestation/commit/7bd32f3fce5ed601f9d820b9078190fd82a0eccc))
* streaming writes — stage large files without buffering in memory ([6202d71](https://github.com/UCSD-E4E/synology-filestation/commit/6202d71dc8921742a27f11a6a42ea3579a5815e5))
* streaming writes (stage large files without buffering in memory) ([8cf31a2](https://github.com/UCSD-E4E/synology-filestation/commit/8cf31a2546f583131b7c611bb9ca3595a29d6af8))
* throttle bulk transfers to protect the NAS from saturation ([8ee8d7a](https://github.com/UCSD-E4E/synology-filestation/commit/8ee8d7a3534cb2af2e58ae2a4d407ce1ed4ed1f7))
* throttle bulk transfers to protect the NAS from saturation ([83ddfac](https://github.com/UCSD-E4E/synology-filestation/commit/83ddfaca72952e44193899bf00faa62affdf5dd4))
* transparent read/write backend selection with circuit-breaker fallback ([090d032](https://github.com/UCSD-E4E/synology-filestation/commit/090d0328455b06682d88408abce369f2606d490b))
* transparent SMB-preferred read/write with HTTP fallback (selection + auto-wiring) ([9282f01](https://github.com/UCSD-E4E/synology-filestation/commit/9282f016c0467fbfb63aa19f6c221f0dab262785))


### Bug Fixes

* address Copilot review on the write path ([3db9c36](https://github.com/UCSD-E4E/synology-filestation/commit/3db9c36a36a43b96c43c8a0ad206e1774aa1a981))


### Miscellaneous Chores

* release 0.2.0 ([fae7859](https://github.com/UCSD-E4E/synology-filestation/commit/fae7859d5a3489c0b07343768af772f3fb2edcce))

## [0.1.20](https://github.com/UCSD-E4E/synology-filestation/compare/synology-filestation-core-v0.1.19...synology-filestation-core-v0.1.20) (2026-06-04)


### Features

* GUI calls the Rust core directly via a native FFI binding ([603e47d](https://github.com/UCSD-E4E/synology-filestation/commit/603e47de958a787974c387d1e98e28688344b30b))


### Bug Fixes

* address code-review findings (correctness, cleanup, altitude) ([7631694](https://github.com/UCSD-E4E/synology-filestation/commit/763169458a7e11041726c29a5941b04bbaa84bce))

## [0.1.19](https://github.com/UCSD-E4E/synology-filestation/compare/synology-filestation-core-v0.1.18...synology-filestation-core-v0.1.19) (2026-05-07)


### Miscellaneous Chores

* **synology-filestation-core:** Synchronize synology-filestation versions

## [0.1.18](https://github.com/UCSD-E4E/synology-filestation/compare/synology-filestation-core-v0.1.17...synology-filestation-core-v0.1.18) (2026-05-07)


### Miscellaneous Chores

* **synology-filestation-core:** Synchronize synology-filestation versions

## [0.1.17](https://github.com/UCSD-E4E/synology-filestation/compare/synology-filestation-core-v0.1.16...synology-filestation-core-v0.1.17) (2026-05-07)


### Features

* **core:** auto-relogin, atomic download_to_path, JSON envelope detection ([fb9d4ac](https://github.com/UCSD-E4E/synology-filestation/commit/fb9d4acf01d920fe7e1d30dd434a662d7693e87a))
* Python bindings + fsspec backend (synofs) ([ae100f3](https://github.com/UCSD-E4E/synology-filestation/commit/ae100f372b37f54d3e41aa780db2bfc3f48b0140))
