package main

import "testing"

func TestPaddingRecordLimitForMSS(t *testing.T) {
	if got, want := paddingRecordLimitForMSS(1460), 1428; got != want {
		t.Fatalf("IPv4 MSS limit = %d, want %d", got, want)
	}
	if got, want := paddingRecordLimitForMSS(1440), 1408; got != want {
		t.Fatalf("IPv6 MSS limit = %d, want %d", got, want)
	}
	if got, want := paddingRecordLimitForMSS(0), fallbackTCPMSS-tlsRecordOverheadReserve; got != want {
		t.Fatalf("fallback limit = %d, want %d", got, want)
	}
}

func TestPadBucketRespectsMSSLimit(t *testing.T) {
	limit := paddingRecordLimitForMSS(1460) // 1428 bytes of TLSVPN plaintext

	cases := []struct {
		wire int
		want int
	}{
		// 10 + 1200 = 1210, so the normal 1280 bucket still applies.
		{wire: 1200, want: 70},
		// The next static bucket is 1600, but MSS-aware padding caps it at 1428.
		{wire: 1290, want: 128},
		{wire: 1400, want: 18},
		// Already at/over the safe target: do not add padding that can only
		// increase segmentation.
		{wire: 1418, want: 0},
		{wire: 1540, want: 0},
	}
	for _, tc := range cases {
		if got := padBucket(tc.wire, limit); got != tc.want {
			t.Fatalf("padBucket(wire=%d, limit=%d) = %d, want %d", tc.wire, limit, got, tc.want)
		}
	}

	// Compatibility helper without a limit keeps the historical bucket table;
	// only real socket send paths opt into the MSS ceiling.
	if got := padBucket(1540); got != 50 {
		t.Fatalf("uncapped 1600 bucket changed: got pad=%d want=50", got)
	}
}
