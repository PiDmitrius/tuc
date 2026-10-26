// Command tuc runs the test GOST certification authority.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/PiDmitrius/tuc/internal/mp"
	"github.com/PiDmitrius/tuc/internal/tuc"
)

var version = "dev"

const usage = `tuc version                print the build version
tuc keygen                 print a new service secret
tuc serve [flags]           serve sealed unless -secret is explicit
tuc unseal [-socket path] [-initialize]  deliver a secret from stdin
tuc status [-socket path]   print sealed or ready
tuc link [-socket path] ID  replace and print the admin link through the local socket (same uid, no secret)
tuc backup [-db tuc.db] FILE  make a consistent SQLite snapshot (new file, 0600)
tuc usage [-db tuc.db]      root CAs by their last use, the least used first
tuc delete [-db tuc.db] ID  delete the CA ID with everything under it, revoked under its parent
`

func main() {
	log.SetFlags(0)
	if err := tuc.ProtectMemory(); err != nil {
		log.Fatal("cannot disable memory dumps: ", err)
	}
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			log.Fatal(err)
		}
		fmt.Println(tuc.EncodeSecret(k))
		clear(k)
	case "version":
 fmt.Println(version)
 case "serve":
		if err := serve(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "unseal", "status", "link":
		local(os.Args[1], os.Args[2:])
	case "backup":
		fs := flag.NewFlagSet("backup", flag.ExitOnError)
		db := fs.String("db", "tuc.db", "source SQLite database (may be in use)")
		fs.Parse(os.Args[2:])
		if fs.NArg() != 1 {
			log.Fatal("backup: exactly one destination file is required")
		}
		if err := backup(*db, fs.Arg(0)); err != nil {
			log.Fatal("backup: ", err)
		}
	case "usage":
		fs := flag.NewFlagSet("usage", flag.ExitOnError)
		db := fs.String("db", "tuc.db", "SQLite database of the CAs")
		fs.Parse(os.Args[2:])
		if err := tuc.Usage(*db, os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "delete":
		fs := flag.NewFlagSet("delete", flag.ExitOnError)
		db := fs.String("db", "tuc.db", "SQLite database of the CAs")
		fs.Parse(os.Args[2:])
		if fs.NArg() != 1 {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		if err := tuc.Delete(*db, fs.Arg(0)); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", ":8080", "listen address")
	base := fs.String("base", "", "URL of the pages and issuance, e.g. https://tuc.example")
	publish := fs.String("publish", "", "publication URL for AIA, CRL, OCSP and TSP; defaults to -base")
	db := fs.String("db", "tuc.db", "SQLite database of the CAs")
	secretFile := fs.String("secret", "", "startup secret file, - for stdin; omitted starts sealed")
	socket := fs.String("unseal-socket", tuc.DefaultSocket, "local status and unseal socket (private directory required)")
	initialize := fs.Bool("initialize", false, "initialize an empty database with explicit -secret")
	fs.Parse(args)
	if *base == "" {
		return fmt.Errorf("serve: -base is required")
	}
	if fs.NArg() != 0 || (*initialize && *secretFile == "") {
		return fmt.Errorf("serve: -initialize requires -secret; unexpected arguments are not allowed")
	}
	ctx, err := mp.Open()
	if err != nil {
		return err
	}
	s, err := tuc.NewService(ctx, *base, *db, *publish)
	if err != nil {
		return err
	}
	defer s.Close()
	if *secretFile != "" {
		if err := startupSecret(s, *secretFile, *initialize); err != nil {
			return err
		}
	}
	stop, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	listener, err := tuc.ListenLocal(*socket)
	if err != nil {
		return err
	}
	localDone := make(chan error, 1)
	go func() { localDone <- s.ServeLocal(listener) }()
	var connections sync.WaitGroup
	srv := &http.Server{Addr: *listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Minute}
	srv.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			connections.Add(1)
		case http.StateClosed, http.StateHijacked:
			connections.Done()
		}
	}
	httpDone := make(chan error, 1)
	go func() { httpDone <- srv.ListenAndServe() }()
	log.Printf("tuc on %s as %s; state: %s; socket: %s", *listen, *base, s.State(), *socket)
	var runErr error
	select {
	case <-stop.Done():
	case err := <-httpDone:
		httpDone = nil
		if err != nil && err != http.ErrServerClosed {
			runErr = err
		}
	case err := <-localDone:
		runErr = err
		localDone = nil
	}
	shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	if err := srv.Shutdown(shutdown); err != nil {
		srv.Close()
	}
	listener.Close()
	if httpDone != nil {
		<-httpDone
	}
	connections.Wait()
	if localDone != nil {
		<-localDone
	}
	return runErr
}

func startupSecret(s *tuc.Service, path string, initialize bool) error {
	f := os.Stdin
	if path != "-" {
		var err error
		f, err = os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
	}
	raw, err := tuc.ReadInputSecret(f)
	if err != nil {
		return err
	}
	defer clear(raw)
	return s.Unseal(raw, initialize)
}

func local(command string, args []string) {
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	socket := fs.String("socket", tuc.DefaultSocket, "local status and unseal socket")
	initialize := false
	if command == "unseal" {
		fs.BoolVar(&initialize, "initialize", false, "initialize an empty database; never replace an existing verifier")
	}
	fs.Parse(args)
	if command == "link" {
		if fs.NArg() != 1 {
			log.Fatal("usage: tuc link [-socket path] ID")
		}
		link, err := tuc.LocalLink(*socket, fs.Arg(0))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(link)
		return
	}
	if fs.NArg() != 0 {
		log.Fatal("unexpected arguments; unseal reads the secret only from stdin")
	}
	var raw []byte
	if command == "unseal" {
		var err error
		raw, err = tuc.ReadInputSecret(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		defer clear(raw)
	}
	state, err := tuc.LocalRequest(*socket, raw, initialize)
	if err != nil {
		clear(raw)
		log.Fatal(err)
	}
	fmt.Println(state)
}
