# lfuzzo

External fuzz tests for [lneto](https://github.com/soypat/lneto), using only its public API.

## Package split

Packages are split by how fuzz inputs are generated. What counts as a failure is shared.

| Package     | Strategy |
|-------------|----------|
| `synth`     | Builds valid frames from fuzz bytes (checksums, ports and transaction IDs fixed up) and feeds them to a `xnet.StackAsync` with every service active. |
| `roundtrip` | Codec fuzzing: decode, encode, decode again, and compare. |
| `regress`   | Fixed tests for bugs found by fuzzing. No fuzzing. |
| `check`     | Shared oracles (well-formed egress frames, lengths, checksums). Not a test package. |

## Fuzzing the stack

`FuzzIngressMulti` reaches the most of lneto. It sends a stream of crafted IPv4, IPv6 and raw Ethernet packets into a stack with fuzzed MTU and ICMP queue size, while DHCP, DNS, NTP, ICMP, NDP and ARP are all active.

```sh
go test -run XXX -fuzz 'FuzzIngressMulti$' -fuzztime 5m ./synth/
```

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
