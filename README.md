# lfuzzo

External fuzz tests for [lneto](https://github.com/soypat/lneto), using only its public API.

## Package split

Packages are split by how fuzz inputs are generated. What counts as a failure is shared.

| Package     | Strategy |
|-------------|----------|
| `mutate`    | Intercept packets between two `xnet.StackAsync` at random and mutates their contents. |
| `synth`     | Build valid frames from fuzz bytes (checksums, ports and transaction IDs fixed up) and feeds them to a `xnet.StackAsync` with every service active. |
| `roundtrip` | Codec fuzzing: decode, encode, decode again, and compare. |
| `regress`   | Fixed tests for bugs found by fuzzing. No fuzzing. |
| `check`     | Shared oracles (well-formed egress frames, lengths, checksums). Not a test package. |

## Fuzzing the stack

`FuzzHTTPClientServer` reaches the most critical part of lneto. Today the `tcp` and `httphi` packages are used by a large number of people in the embedded space. This fuzz test fuzzes the entire Ethernet+IPv4+TCP+HTTP stack:

```sh
go test -run XXX -fuzz 'FuzzHTTPClientServer$' -fuzzminimizetime 240s -fuzztime 5m ./mutation/
```
A high value for flag `-fuzzminimizetime t` ensures a decent amount of time is allocated to minimizing the failing input.

After a failure cases are found you may replay them by just running tests:
```sh
go test ./...
```

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

## Fuzz corpus and seeding new machines
Fuzz corpus is located at `$GOCACHE/fuzz`. Following command works in bash, zsh and PowerShell:
```sh
# Will list different lfuzzo fuzz folders
ls "$(go env GOCACHE)/fuzz/github.com/soypat/lfuzzo"
```
This is where "interesting" results are persisted. They can be used to seed a machine before it begins fuzzing for the first time.

## Contributing
PRs welcome!