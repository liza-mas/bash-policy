package filelock

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const (
	defaultLockTimeout = 10 * time.Second
	lockCheckInterval  = 100 * time.Millisecond
)

type FileLock struct {
	lockPath    string
	ownerPath   string
	lockTimeout time.Duration
}

type ownerMetadata struct {
	Version    int    `json:"version"`
	PID        int    `json:"pid"`
	Hostname   string `json:"hostname,omitempty"`
	Operation  string `json:"operation"`
	AcquiredAt string `json:"acquired_at"`
}

func New(protectedPath string) *FileLock {
	return &FileLock{
		lockPath:    protectedPath + ".lock",
		ownerPath:   protectedPath + ".lock.owner.json",
		lockTimeout: defaultLockTimeout,
	}
}

func (fl *FileLock) WithLockOperation(operation string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(fl.lockPath), 0o755); err != nil {
		return fmt.Errorf("create lock directory: %w", err)
	}
	file, err := os.OpenFile(fl.lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer file.Close()

	deadline := time.Now().Add(fl.lockTimeout)
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("lock unavailable after %s", fl.lockTimeout)
		}
		time.Sleep(lockCheckInterval)
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)

	fl.writeOwnerMetadata(operation)
	return fn()
}

func (fl *FileLock) writeOwnerMetadata(operation string) {
	hostname, _ := os.Hostname()
	metadata := ownerMetadata{
		Version:    1,
		PID:        os.Getpid(),
		Hostname:   hostname,
		Operation:  operation,
		AcquiredAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(fl.ownerPath), filepath.Base(fl.ownerPath)+".tmp-*")
	if err != nil {
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	_ = os.Rename(tmpPath, fl.ownerPath)
}
