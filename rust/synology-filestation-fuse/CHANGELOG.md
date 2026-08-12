# Changelog

## [0.3.0](https://github.com/UCSD-E4E/synology-filestation/compare/synology-filestation-fuse-v0.2.1...synology-filestation-fuse-v0.3.0) (2026-08-12)


### ⚠ BREAKING CHANGES

* TLS certificate verification is now on by default. A stock DSM appliance presents a self-signed certificate and will be rejected until it is trusted or verification is explicitly turned off.

### Features

* **core:** stream large uploads in slices instead of buffering whole files ([0220d73](https://github.com/UCSD-E4E/synology-filestation/commit/0220d735ee1a6d95076e25aaa36a626c4ea0550b))
* **core:** stream large uploads in slices instead of buffering whole files ([e8cce35](https://github.com/UCSD-E4E/synology-filestation/commit/e8cce358a289aab34efe5d71938b6927ae7253ef))
* **fuse:** add --password-stdin, and warn when the password comes from argv ([6193e2b](https://github.com/UCSD-E4E/synology-filestation/commit/6193e2b2cf80fad425705e6cfc2e2405ddb2f6d1))
* verify TLS certificates by default, and keep credentials out of the URL ([6594fda](https://github.com/UCSD-E4E/synology-filestation/commit/6594fdab53978d6f2e3de454d05aa338a848b917))


### Bug Fixes

* address review feedback on the slice-upload path ([f525881](https://github.com/UCSD-E4E/synology-filestation/commit/f525881b49e146f5413c655c50f68d39e2ba6e78))
* **fuse:** bound the wait for an in-flight read-cache block ([a0822a3](https://github.com/UCSD-E4E/synology-filestation/commit/a0822a35d4149be64ef14da93b49a2df70bb1fc4))
* **fuse:** create write-spill temp files with owner-only permissions ([1e78f20](https://github.com/UCSD-E4E/synology-filestation/commit/1e78f20c9e5bf19ca4445b368caa3c130c0f9d58))
* **fuse:** stop silently losing data on flush, truncate, move and short reads ([7e8687d](https://github.com/UCSD-E4E/synology-filestation/commit/7e8687dd469124a981fb38202450cb6b721d0fc8))
* seven data-loss and corruption defects found in review (tier 1) ([6b044aa](https://github.com/UCSD-E4E/synology-filestation/commit/6b044aad69c4ed0f4ab84807ec6a1cc5ab8cc7ae))
* stop leaking the session id and passwords into logs ([1ad289a](https://github.com/UCSD-E4E/synology-filestation/commit/1ad289a27a7df52121e59b57c72d67c47dd66a3c))
* **webdav:** use the shared upload payload fork ([7f5cf52](https://github.com/UCSD-E4E/synology-filestation/commit/7f5cf528c7607467d5d43375da8720560715a08f))

## [0.2.1](https://github.com/UCSD-E4E/synology-filestation/compare/synology-filestation-fuse-v0.2.0...synology-filestation-fuse-v0.2.1) (2026-07-30)


### Miscellaneous Chores

* **synology-filestation-fuse:** Synchronize synology-filestation versions

## [0.2.0](https://github.com/UCSD-E4E/synology-filestation/compare/synology-filestation-fuse-v0.1.20...synology-filestation-fuse-v0.2.0) (2026-07-29)


### Features

* auto-prefer SMB in all consumers (transparent, no API change) ([e9c123a](https://github.com/UCSD-E4E/synology-filestation/commit/e9c123a69c4ec9556dfed02d5420244f02ac5a28))
* streaming reads — fetch large files straight to disk (+ auto_attach) ([6f7d473](https://github.com/UCSD-E4E/synology-filestation/commit/6f7d473085c73fdfe98ea17c29f4418f3e9544ad))
* streaming reads (fetch large files straight to disk) ([7bd32f3](https://github.com/UCSD-E4E/synology-filestation/commit/7bd32f3fce5ed601f9d820b9078190fd82a0eccc))
* streaming writes — stage large files without buffering in memory ([6202d71](https://github.com/UCSD-E4E/synology-filestation/commit/6202d71dc8921742a27f11a6a42ea3579a5815e5))
* streaming writes (stage large files without buffering in memory) ([8cf31a2](https://github.com/UCSD-E4E/synology-filestation/commit/8cf31a2546f583131b7c611bb9ca3595a29d6af8))
* transparent SMB-preferred read/write with HTTP fallback (selection + auto-wiring) ([9282f01](https://github.com/UCSD-E4E/synology-filestation/commit/9282f016c0467fbfb63aa19f6c221f0dab262785))


### Bug Fixes

* make internal core dependency path-only so 0.x bumps resolve ([71152cb](https://github.com/UCSD-E4E/synology-filestation/commit/71152cb28ad8dbab1dd85aefe771530acdf00562))
* make internal workspace deps path-only so 0.x bumps resolve ([da68cf8](https://github.com/UCSD-E4E/synology-filestation/commit/da68cf81ab6fea58a2b1dbfe2693e82f2ddf752d))


### Miscellaneous Chores

* release 0.2.0 ([fae7859](https://github.com/UCSD-E4E/synology-filestation/commit/fae7859d5a3489c0b07343768af772f3fb2edcce))

## [0.1.20](https://github.com/UCSD-E4E/synology-filestation/compare/synology-filestation-fuse-v0.1.19...synology-filestation-fuse-v0.1.20) (2026-06-04)


### Features

* GUI calls the Rust core directly via a native FFI binding ([603e47d](https://github.com/UCSD-E4E/synology-filestation/commit/603e47de958a787974c387d1e98e28688344b30b))
* GUI calls the Rust core directly via a native FFI binding ([8149a2f](https://github.com/UCSD-E4E/synology-filestation/commit/8149a2fcd0fabf1705298725b3c9e5763225fb77))


### Bug Fixes

* address third round of Copilot review feedback ([e60373f](https://github.com/UCSD-E4E/synology-filestation/commit/e60373fee0a4e6fecc33d12ee2b6231b78b906ef))

## [0.1.19](https://github.com/UCSD-E4E/synology-filestation/compare/synology-filestation-fuse-v0.1.18...synology-filestation-fuse-v0.1.19) (2026-05-07)


### Bug Fixes

* **fuser:** address Copilot review feedback on PR [#71](https://github.com/UCSD-E4E/synology-filestation/issues/71) ([72e5813](https://github.com/UCSD-E4E/synology-filestation/commit/72e5813b5efe54fa1b3728a89a2d2a362eea122e))

## [0.1.18](https://github.com/UCSD-E4E/synology-filestation/compare/synology-filestation-fuse-v0.1.17...synology-filestation-fuse-v0.1.18) (2026-05-07)


### Miscellaneous Chores

* **synology-filestation-fuse:** Synchronize synology-filestation versions

## [0.1.17](https://github.com/UCSD-E4E/synology-filestation/compare/synology-filestation-fuse-v0.1.16...synology-filestation-fuse-v0.1.17) (2026-05-07)


### Features

* Python bindings + fsspec backend (synofs) ([ae100f3](https://github.com/UCSD-E4E/synology-filestation/commit/ae100f372b37f54d3e41aa780db2bfc3f48b0140))
