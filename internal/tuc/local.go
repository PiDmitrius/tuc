package tuc

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const DefaultSocket = "/run/tuc/unseal.sock"

// ListenLocal owns a socket in a private directory of the service user.
func ListenLocal(path string) (*net.UnixListener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 || !ownedByUser(info) {
		return nil, errors.New("socket directory must be owned by the service user with mode 0700")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 || !ownedByUser(info) {
			return nil, errors.New("refusing to replace socket path")
		}
		conn, err := net.DialTimeout("unix", path, time.Second)
		if err == nil {
			conn.Close()
			return nil, errors.New("socket is already in use")
		}
		if !refused(err) {
			return nil, err
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

func localCode(err error) string {
	switch {
	case err == nil:
		return "ready"
	case errors.Is(err, ErrSecret):
		return "wrong-secret-or-damaged-database"
	case errors.Is(err, ErrInitialize):
		return "initialize-required"
	case errors.Is(err, ErrConflict):
		return "conflict"
	default:
		return "invalid-request-or-database-error"
	}
}

// ServeLocal accepts bounded binary deliveries, never a public HTTP request.
func (s *Service) ServeLocal(listener *net.UnixListener) error {
	slots := make(chan struct{}, 4)
	var pending sync.WaitGroup
	defer pending.Wait()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
			pending.Add(1)
			go func() {
				defer pending.Done()
				defer func() { <-slots }()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				if !peerAllowed(conn) {
					return
				}
				in, err := io.ReadAll(io.LimitReader(conn, 42))
				defer clear(in)
				if err != nil {
					return
				}
				if len(in) == 1 && in[0] == 0 {
					fmt.Fprintln(conn, s.State())
					return
				}
				if len(in) == 41 && in[0] == 3 {
					if s.secret.Load() == nil {
						fmt.Fprintln(conn, "error:sealed")
						return
					}
					id := strings.ToUpper(string(in[1:]))
					if !idRe.MatchString(id) {
						fmt.Fprintln(conn, "error:invalid-id")
						return
					}
					generation, err := s.st.tokenGeneration(id, "admin", true)
					if err != nil {
						fmt.Fprintln(conn, "error:CA-not-found-or-database-error")
						return
					}
					fmt.Fprintln(conn, s.caURL(id)+"#token="+s.secret.Load().Token(id, "admin", generation))
					return
				}
				if len(in) != 33 || (in[0] != 1 && in[0] != 2) {
					fmt.Fprintln(conn, "error:invalid-request")
					return
				}
				err = s.Unseal(in[1:], in[0] == 2)
				code := localCode(err)
				if err != nil {
					log.Printf("tuc unseal: %s", code)
					fmt.Fprintln(conn, "error:"+code)
				} else {
					fmt.Fprintln(conn, code)
				}
			}()
		default:
			conn.Close()
		}
	}
}

// LocalRequest sends a status request or a raw secret only over a Unix socket.
func LocalRequest(path string, raw []byte, initialize bool) (string, error) {
	var payload [33]byte
	defer clear(payload[:])
	n := 1
	if raw != nil {
		if len(raw) != 32 {
			return "", errors.New("secret must be 32 bytes")
		}
		payload[0] = 1
		if initialize {
			payload[0] = 2
		}
		copy(payload[1:], raw)
		n = len(payload)
	}
	response, err := localExchange(path, payload[:n])
	if err != nil {
		return "", err
	}
	state := strings.TrimSpace(response)
	if state == "ready" || (raw == nil && state == "sealed") {
		return state, nil
	}
	if strings.HasPrefix(state, "error:") {
		return "", errors.New(strings.TrimPrefix(state, "error:"))
	}
	return "", errors.New("invalid local confirmation; check tuc status")
}

func localExchange(path string, payload []byte) (string, error) {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return "", errors.New("cannot connect to local socket")
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if !peerAllowed(conn) {
		return "", errors.New("socket peer is not the current user")
	}
	if _, err := conn.Write(payload); err != nil {
		return "", errors.New("cannot deliver local request")
	}
	if err := conn.CloseWrite(); err != nil {
		return "", err
	}
	response, err := io.ReadAll(io.LimitReader(conn, 4096))
	if err != nil {
		return "", errors.New("no local confirmation; check tuc status")
	}
	return string(response), nil
}

func LocalLink(path, id string) (string, error) {
	id = strings.ToUpper(id)
	if !idRe.MatchString(id) {
		return "", errors.New("invalid CA id")
	}
	response, err := localExchange(path, append([]byte{3}, []byte(id)...))
	if err != nil {
		return "", err
	}
	link := strings.TrimSpace(response)
	if strings.HasPrefix(link, "error:") {
		return "", errors.New(strings.TrimPrefix(link, "error:"))
	}
	if !strings.Contains(link, "/"+id+"#token=") {
		return "", errors.New("invalid local link response")
	}
	return link, nil
}
