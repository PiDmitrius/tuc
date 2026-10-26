package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PiDmitrius/tuc/internal/tuc"
)

func TestCommandProcess(t *testing.T) {
	if os.Getenv("TUC_TEST_COMMAND") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"tuc"}, os.Args[i+1:]...)
			break
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "check-dumps" {
		if err := tuc.ProtectMemory(); err != nil {
			os.Exit(2)
		}
		var limit syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &limit); err != nil || limit.Cur != 0 || limit.Max != 0 {
			os.Exit(3)
		}
		value, _, err := syscall.Syscall6(syscall.SYS_PRCTL, 3, 0, 0, 0, 0, 0)
		if err != 0 || value != 0 {
			os.Exit(4)
		}
		os.Exit(0)
	}
	main()
	os.Exit(0)
}

func command(args ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestCommandProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "TUC_TEST_COMMAND=1")
	return cmd
}

func TestCLIUnseal(t *testing.T) {
	if out, err := command("check-dumps").CombinedOutput(); err != nil {
		t.Fatalf("dump protection: %v %s", err, out)
	}
	dir := t.TempDir()
	socket := filepath.Join(dir, "run", "socket")
	db := filepath.Join(dir, "tuc.db")
	var logs bytes.Buffer
	start := func(extra ...string) func() {
		t.Helper()
		args := append([]string{"serve", "-base", "http://tuc.test", "-listen", "127.0.0.1:0", "-db", db, "-unseal-socket", socket}, extra...)
		cmd := command(args...)
		cmd.Stdout = &logs
		cmd.Stderr = &logs
		cmd.Stdin = strings.NewReader("unused stdin")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			cmd.Process.Signal(syscall.SIGTERM)
			if err := cmd.Wait(); err != nil {
				t.Errorf("serve: %v %s", err, logs.String())
			}
		}
		t.Cleanup(stop)
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(socket); err == nil {
				break
			}
			if time.Now().After(deadline) {
				stop()
				t.Fatal("socket did not start")
			}
			time.Sleep(10 * time.Millisecond)
		}
		return stop
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	encoded := tuc.EncodeSecret(raw)
	run := func(input string, args ...string) (string, error) {
		cmd := command(args...)
		cmd.Stdin = strings.NewReader(input)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	stop := start("-publish", "http://publication.test")
	if out, err := run("", "status", "-socket", socket); err != nil || strings.TrimSpace(out) != "sealed" {
		t.Fatalf("sealed status: %v %s", err, out)
	}
	if _, err := run(encoded, "unseal", "-socket", socket); err == nil {
		t.Fatal("implicitly initialized")
	}
	if out, err := run(encoded+"\n", "unseal", "-socket", socket, "-initialize"); err != nil || strings.TrimSpace(out) != "ready" {
		t.Fatalf("unseal: %v %s", err, out)
	}
	if _, err := run(encoded, "unseal", "-socket", socket); err != nil {
		t.Fatal(err)
	}
	if out, err := run("", "status", "-socket", socket); err != nil || strings.TrimSpace(out) != "ready" {
		t.Fatalf("ready status: %v %s", err, out)
	}
	stop()
	stop = start()
	if out, err := run("", "status", "-socket", socket); err != nil || strings.TrimSpace(out) != "sealed" {
		t.Fatalf("restart status: %v %s", err, out)
	}
	if _, err := run(encoded, "unseal", "-socket", socket); err != nil {
		t.Fatal(err)
	}
	stop()
	secretFile := filepath.Join(dir, "compatibility-secret")
	if err := os.WriteFile(secretFile, []byte(encoded), 0600); err != nil {
		t.Fatal(err)
	}
	stop = start("-secret", secretFile)
	if out, err := run("", "status", "-socket", socket); err != nil || strings.TrimSpace(out) != "ready" {
		t.Fatalf("compatibility file: %v %s", err, out)
	}
	stop()
	args := []string{"serve", "-base", "http://tuc.test", "-listen", "127.0.0.1:0", "-db", db, "-unseal-socket", socket, "-secret", "-"}
	cmd := command(args...)
	cmd.Stdin = strings.NewReader(encoded)
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatal("stdin compatibility did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cmd.Process.Signal(syscall.SIGTERM)
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), encoded) {
		t.Fatal("secret leaked to service logs")
	}
	wrong := bytes.Clone(raw)
	wrong[0] ^= 1
	if _, err := run(tuc.EncodeSecret(wrong), args...); err == nil {
		t.Fatal("wrong startup secret accepted")
	}
	clear(wrong)
	if _, err := run("", "serve", "-base", "http://tuc.test", "-initialize"); err == nil {
		t.Fatal("initialize without secret accepted")
	}
	if out, err := run("bad\n", "unseal", "-socket", socket); err == nil || strings.Contains(out, "bad") {
		t.Fatalf("invalid input: %v %s", err, out)
	}
}
