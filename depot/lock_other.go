//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package depot

// Lock is a no-op on platforms without directory advisory locks.
func (d *FileDepot) Lock() (func(), error) {
	return func() {}, nil
}
