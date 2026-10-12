// Package trace gates verbose tracing of fuzz runs behind the lfuzzotrace build tag:
//
//	go test -tags=lfuzzotrace -run 'FuzzHTTPClientServer/da1c32f8b4f9a428' -v ./mutation/
//
// Guard trace code with [Enabled] so it compiles away in normal and fuzzing builds:
//
//	if trace.Enabled {
//		t.Logf("SEG %+v", seg)
//	}
package trace
