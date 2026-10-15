# Fuzzing lneto

This document describes how lfuzzo fuzzes and property-tests
[lneto](https://github.com/soypat/lneto). lfuzzo uses only lneto's public
API. How lneto's own tests are written, including the regression tests for
bugs found here, is described in lneto's
[docs/TESTING.md](https://github.com/soypat/lneto/blob/main/docs/TESTING.md).

## Running

`go test ./...` runs every seed and every committed corpus entry, without
fuzzing. Fuzz one target with:

```sh
go test -run XXX -fuzz 'FuzzStackPair$' -fuzztime 5m ./model/
```

Add `-fuzzminimizetime 240s` for long-running targets so a failing input is
minimized. Inputs that reach new code are kept in `$(go env GOCACHE)/fuzz`,
which can seed another machine before it starts fuzzing.

## Where a fuzzer belongs

Packages are split by how inputs are generated; see the table in the
[README](../README.md). Pick the package by strategy:

- `roundtrip` for one codec on its own: decode, encode, decode again.
- `synth` for crafted frames into one stack with every service active.
- `mutation` for traffic between two stacks, rewritten on the wire.
- `model` for scripted application actions on two stacks or Handlers,
  including property-based testing with Hegel.
- `regress` for fixed tests of bugs found by fuzzing, without fuzzing.

Add a target to the existing file of its package and topic. Its doc comment
states what must hold and the command that fuzzes it, as the existing targets
do. Seeds come from real traffic or from earlier findings; a finding kept as a
seed gets a comment naming what it found.

## What counts as a failure

A panic is always a failure. Beyond panics, a target needs an oracle, a check
that catches wrong behaviour that does not crash:

- **Well-formed egress.** `check.Egress` and `check.Drain` assert lengths,
  checksums and that no frame exceeds the MTU. Shared oracles go in `check`.
- **Exact capacity.** Give lneto buffers with no spare capacity, so a read or
  write past the length panics instead of going unnoticed.
- **Determinism.** The same input must give the same output. `FuzzOracle`
  runs a stream twice with different bytes past each frame's length.
- **Roundtrip.** Decoding the encoding of a decoded value gives the same value.
- **No allocation.** Handling traffic must not allocate in steady state, see
  `FuzzNoAlloc`.
- **Invariants of the protocol.** Model targets check what the RFC and
  `net.Conn` require: TCP delivers a prefix of what was written, data written
  before Close arrives followed by EOF, peers settle in valid states.

Accept only the errors lneto documents for the situation, such as
`lneto.ErrPacketDrop` for an input it rejects. An unexpected error is a
failure.

## Property-based testing

`model/hegel_test.go` drives two `tcp.Handler`s with
[Hegel](https://github.com/hegeldev/hegel-go), which generates action
sequences and shrinks a failure to a short one. The same model also runs as a
seeded random baseline and as a Go fuzz target. Hegel loads a native engine
embedded in its module, so the file builds only on the platforms libhegel is
built for. Raise the number of cases with:

```sh
go test -run 'TestTCPStateful$' ./model/ -cases=10000 -steps=200
```

## When a fuzzer finds a failure

1. Run only the failing input, traced with the `lfuzzotrace` build tag:
   `go test -tags=lfuzzotrace -run 'FuzzX/<input>' -v ./pkg/`.
2. Clone lneto into `./lneto` and use it with `go work init && go work use .
   ./lneto`.
3. In lneto, write a minimal failing test at the lowest layer that shows the
   bug, for TCP an `ExchangeTest` in `tcp/tcp_test.go`, then the smallest fix.
   Open the fix as its own lneto pull request.
4. Once it is merged, update lfuzzo's lneto with
   `GOPROXY=direct go get -u github.com/soypat/lneto` and keep the input as a
   seed if it guards against something no other seed reaches.

A failing input is written to `testdata/fuzz/<target>/` of the package. It
can be shared by posting the file's contents. `.gitignore` ignores files
without an extension, so commit a corpus file with `git add -f`.
