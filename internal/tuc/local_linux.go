package tuc

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

func ownedByUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func refused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

func peerAllowed(conn *net.UnixConn) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	allowed := false
	err = raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		allowed = err == nil && cred.Uid == uint32(os.Geteuid())
	})
	return err == nil && allowed
}

// ProtectMemory disables core files and Linux process dump access.
func ProtectMemory() error {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		return err
	}
	_, _, err := syscall.Syscall6(syscall.SYS_PRCTL, 4, 0, 0, 0, 0, 0)
	if err != 0 {
		return err
	}
	return nil
}

// ReadInputSecret hides terminal input; pipes are consumed to EOF.
func ReadInputSecret(file *os.File) ([]byte, error) {
	var saved syscall.Termios
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&saved)))
	if err != 0 {
		if err != syscall.ENOTTY {
			return nil, err
		}
		return ReadSecret(file)
	}
	hidden := saved
	hidden.Lflag &^= syscall.ECHO
	_, _, err = syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), syscall.TCSETS, uintptr(unsafe.Pointer(&hidden)))
	if err != 0 {
		return nil, err
	}
	defer syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), syscall.TCSETS, uintptr(unsafe.Pointer(&saved)))
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	finished := make(chan struct{})
	defer close(finished)
	defer signal.Stop(signals)
	go func() {
		select {
		case sig := <-signals:
			syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), syscall.TCSETS, uintptr(unsafe.Pointer(&saved)))
			os.Exit(128 + int(sig.(syscall.Signal)))
		case <-finished:
		}
	}()
	defer os.Stderr.Write([]byte("\n"))
	var line [256]byte
	defer clear(line[:])
	for i := range line {
		if _, err := io.ReadFull(file, line[i:i+1]); err != nil {
			return nil, errors.New("cannot read secret line")
		}
		if line[i] == '\n' {
			return ReadSecret(bytes.NewReader(line[:i+1]))
		}
	}
	return nil, errors.New("secret line is too long")
}
