//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package depot

import (
	"os"
	"syscall"
)

// Lock takes an exclusive advisory lock on the depot directory. CRL updates
// read, modify and replace a depot file, so serializing them across processes
// prevents one revocation from overwriting another. The returned function
// releases the lock.
func (d *FileDepot) Lock() (func(), error) {
	if err := os.MkdirAll(d.dirPath, 0755); err != nil {
		return nil, err
	}
	dir, err := os.Open(d.dirPath)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(dir.Fd()), syscall.LOCK_EX); err != nil {
		_ = dir.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(dir.Fd()), syscall.LOCK_UN)
		_ = dir.Close()
	}, nil
}
