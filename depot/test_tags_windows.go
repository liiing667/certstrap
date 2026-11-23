package depot

// windows does not allow 0600 permissions so we need to set test tags to be 0666
var (
	tag  = &Tag{"host.pem", 0666}
	tag2 = &Tag{"host2.pem", 0666}

	// windows does not allow 0440 permissions so we need to set test tags to be 0444
	txnTag1 = &Tag{"txn1.pem", 0444}
	txnTag2 = &Tag{"txn2.pem", 0444}
	txnTag3 = &Tag{"txn3.pem", 0444}
)
