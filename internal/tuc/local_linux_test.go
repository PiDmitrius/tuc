package tuc

import (
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLocalForeignPeerProcess(t *testing.T) {
	if os.Getenv("TUC_FOREIGN_PEER") != "1" {
		return
	}
	path := os.Args[len(os.Args)-1]
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		os.Exit(2)
	}
	conn.Write([]byte{0})
	conn.CloseWrite()
	body, _ := io.ReadAll(conn)
	conn.Close()
	if len(body) != 0 {
		os.Exit(3)
	}
	os.Exit(0)
}

func TestLocalForeignPeer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("credential switch needs root in the test container")
	}
	e := sealedEnv(t, nil)
	dir := t.TempDir()
	if err := os.Chmod(filepath.Dir(dir), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(dir, "run")
	socket := filepath.Join(private, "socket")
	listener, err := ListenLocal(socket)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- e.svc.ServeLocal(listener) }()
	defer func() { listener.Close(); <-done }()
	// The peer check must still deny another uid when filesystem access is allowed.
	if err := os.Chmod(private, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0666); err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "peer-test")
	if err := os.WriteFile(helper, binary, 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(helper, "-test.run=^TestLocalForeignPeerProcess$", "--", socket)
	cmd.Env = append(os.Environ(), "TUC_FOREIGN_PEER=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("foreign uid was not denied after connecting: %v %s", err, out)
	}
}
