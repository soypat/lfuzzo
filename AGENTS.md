After a fuzz finding you must trace failure with -tags=lfuzzotrace build tag to print trace data and run only the exact failing test to omit noise.

The fix is done to lneto clone in local directory ./lneto
`go work init && go work use . ./lneto` uses this repo for tests so you may test as you go.

First you provide a test to lneto at lowest level possible i.e: for TCP ideally for ControlBlock in tcp/tcp_test.go using the readable Exchange testing methodology. Only after writing a minimal failing test you explain the failure. Comment on test is 2 lines max detailing the expected behaviour and what was actually observed. The fix will be a minimal footprint fix prioritizing correctness above all. Comments kept concise, to the point, no fluff.