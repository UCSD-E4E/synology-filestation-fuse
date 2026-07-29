# Changelog

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
