package depot

import "sync"

// depotMutationMu serializes generation-level depot mutations in this process.
// File renames are atomic individually, but a multi-file transaction or a
// key/certificate replacement must not interleave with another generation.
var depotMutationMu sync.Mutex
