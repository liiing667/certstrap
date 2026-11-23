//go:build !windows
// +build !windows

package depot

var (
	tag  = &Tag{"host.pem", 0600}
	tag2 = &Tag{"host2.pem", 0600}

	txnTag1 = &Tag{"txn1.pem", 0440}
	txnTag2 = &Tag{"txn2.pem", 0444}
	txnTag3 = &Tag{"txn3.pem", 0444}
)
