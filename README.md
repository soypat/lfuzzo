# lfuzzo

External fuzz tests for [lneto](https://github.com/soypat/lneto), using only its public API.

## Package split

Packages are split by how fuzz inputs are generated. What counts as a failure is shared.

| Package     | Strategy |
|-------------|----------|
| `mutate`    | Intercept packets between two `xnet.StackAsync` at random and mutates their contents. |
| `synth`     | Build valid frames from fuzz bytes (checksums, ports and transaction IDs fixed up) and feeds them to a `xnet.StackAsync` with every service active. |
| `roundtrip` | Codec fuzzing: decode, encode, decode again, and compare. |
| `model`     | Drive two `xnet.StackAsync` through a fuzzed script of application actions (writes, reads, pings, closes) and check what the stacks must guarantee. |
| `regress`   | Fixed tests for bugs found by fuzzing. No fuzzing. |
| `check`     | Shared oracles (well-formed egress frames, lengths, checksums). Not a test package. |

## Fuzzing the stack

`FuzzHTTPClientServer` reaches the most critical part of lneto. Today the `tcp` and `httphi` packages are used by a large number of people in the embedded space. This fuzz test fuzzes the entire Ethernet+IPv4+TCP+HTTP stack:

```sh
go test -run XXX -fuzz 'FuzzHTTPClientServer$' -fuzzminimizetime 240s ./mutation/
```
A high value for flag `-fuzzminimizetime t` ensures a decent amount of time is allocated to minimizing the failing input.

After a failure cases are found you may replay them by just running tests:
```sh
go test ./...
```

## I think I found a failure!
If while fuzzing you run into a failure it'll look something like so:
```
--- FAIL: FuzzHTTPClientServer (1811.83s)
    --- FAIL: FuzzHTTPClientServer (0.00s)
        dual_test.go:187: did not expect failure: i/o timeout
    
    Failing input written to testdata/fuzz/FuzzHTTPClientServer/675f741665d4dd06
```
Our failure was written to `mutation/testdata/fuzz/FuzzHTTPClientServer/675f741665d4dd06` in this case since we were fuzzing the `mutation` package. The fuzz failure can be shared by cat'ing the file and posting the contents:
```sh
$ cat mutation/testdata/fuzz/FuzzHTTPClientServer/675f741665d4dd06
go test fuzz v1
uint64(10806)
[]byte("B\x01\x0000\xf9\xff\xff00007000007\x00\x00\x01\x00")
```


### Tracing a failure

Build with the `lfuzzotrace` tag to log every segment exchanged, mutations applied, ingress errors and connection state between phases:
```sh
go test -tags=lfuzzotrace -run 'FuzzHTTPClientServer/da1c32f8b4f9a428' -v ./mutation/
```
Tracing code is guarded by the `trace.Enabled` constant in [`internal/trace`](./internal/trace) and compiles away without the tag, so fuzzing speed is unaffected.

## Pulling a specific lneto version + Developing

You may pull a specific in-development branch of lneto by specifying the branch name or commit name. To pull the `ssh3` branch:
```sh
# this will update your go.mod file.
GOPROXY=direct go get -u github.com/soypat/lneto@ssh3
```

Or if you wish to develop lneto locally you may clone lneto and create a `go.work` file pointing to it:

```sh
git clone git@github.com:soypat/lneto.git
go work init
go work use . ./lneto
```

After lneto fix is merged to main update lfuzzo's Lneto version to latest with `go get -u` with direct github query:
```sh
GOPROXY=direct go get -u github.com/soypat/lneto
```

## Fuzz corpus and seeding new machines
Fuzz corpus is located at `$GOCACHE/fuzz`. Following command works in bash, zsh and PowerShell:
```sh
# Will list different lfuzzo fuzz folders
ls "$(go env GOCACHE)/fuzz/github.com/soypat/lfuzzo"
```
This is where "interesting" results are persisted. They can be used to seed a machine before it begins fuzzing for the first time.

## Contributing
PRs welcome!