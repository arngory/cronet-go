# arngory/cronet-go

A fork of [SagerNet/cronet-go](https://github.com/SagerNet/cronet-go), the Go bindings of naiveproxy's libcronet, for
the naive client of [Niko](https://github.com/arngory/niko). The library itself is built from
[arngory/naiveproxy](https://github.com/arngory/naiveproxy) (the `naiveproxy` submodule): the naive stack moved onto
Chromium 158, see its FORK.md.

## Branches

| Branch | What |
|---|---|
| `claude/clever-feynman-w0e2v1` | the source: upstream `main` (`73349ff`) and the changes below. Pull requests go here; a push runs Build (`naive-build.yml`) |
| `go-158` | the Go module Niko takes: the source with the built libcronet in `lib/` (Android arm, arm64, 386 and amd64, Linux amd64, Windows amd64 and arm64). Build writes it on request (`publish`) and replaces it each time |
| `niko/go-158-pins` | the `go-158` commit Niko pins now (`4fe4c13`), kept when `go-158` is replaced |
| `niko/go-154-pins`, `niko/quic-local-roots` | the Chromium 154 line, for Niko's earlier builds |
| `go-158-20261114`, `-2` … `-5` | earlier states of `go-158`; nothing pins them now |
| `main`, `go`, `dev`, `go_dev` | upstream's |

`niko/*` branches are never moved, rewritten or deleted: a pin on a commit that is gone no longer builds. A new pin
gets a branch of its own (`niko/go-158-<YYYYMMDD>`).

## What differs from upstream

- **Chromium 158**: the submodule is arngory/naiveproxy, the naive stack ported from klzgrad's Chromium 154 onto 158.
- **Datagram streams** for naive's UDP over HTTP/3 (connect-udp, raycontrol `docs/spec/naive-udp-v1.md`):
  `DatagramStream`, `DatagramConn` (`datagram_*.go`), with their errors and counters.
- **Certificate pins** for the node's certificate (raycontrol `docs/spec/cert-pin-v1.md`, `niko-pin`): exact server certificates
  (`exact_server_certificates*`) and public key pins with the trust anchors of the Chrome Root Store
  (`chrome_root_store*.go`); an option for QUIC to take a locally trusted root.
- **CONNECT header fields per stream** and `ConnectError` with the status and fields of a refusal
  (`DialEarlyWithHeaders`, `DialContextWithHeaders`; raycontrol `docs/spec/app-attest-v1.md`).
- **Windows** amd64 and arm64 libraries; `libcronet.dll` is loaded from the executable's directory only, not `PATH`.
- **Licenses next to the library**: each `lib/<os>_<arch>` module carries `NOTICE.chromium.txt`, the licenses of
  Chromium and of each third-party component shipped in it (`Shipped` not `no` in its `README.chromium`), as plain
  text. The minimized tree has no `tools/licenses`, so `cmd/build-naive` makes it from those files when it packages
  the libraries.
- **CI** (`naive-build.yml`): Go unit tests and purego cross-builds, the libraries for the platforms above, the test
  module (`test/`: datagram streams against a quic-go server, certificates, roots, CONNECT fields) on Linux and
  Windows; publishing to `go-158` on request.

## Who pins it

| Where | Pin |
|---|---|
| Niko `libcore/go.mod` | `replace` of `github.com/sagernet/cronet-go` and its `lib/*` modules to this fork, `v0.0.0-20261116191843-4fe4c13fa9b2`: `go-158` at `4fe4c13`, kept by `niko/go-158-pins` |

## Working on it

- A change goes to the source branch by a pull request from a branch of its own, with a test; Build on the merge
  (10 to 20 minutes) runs the tests and builds the libraries. A change to the library itself goes to
  arngory/naiveproxy first, then the submodule moves here ("Update naiveproxy").
- Publishing: Actions → Build → Run workflow with `publish`. It replaces `go-158` with "Build from <source commit>";
  Before Niko moves its pin to the new commit, that commit gets its `niko/go-158-<YYYYMMDD>` branch; the old pin's
  branch stays.
- Checks (`.github/workflows/checks.yml`): "Commit messages" (no bare `#N`; in a fork GitHub links a bare `#N` to
  upstream's issues, so write `arngory/cronet-go#N`) and "Secrets" (gitleaks, rules in `.gitleaks.toml`). Both take
  only the pull request's own line, not upstream's commits.
- A pull request that changes the checks themselves is merged by the owner.
- The rules shared with raycontrol, niko-server and Niko: raycontrol's
  [CONTRIBUTING.md](https://github.com/arngory/raycontrol/blob/main/CONTRIBUTING.md).
