package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/mattn/go-sqlite3"
)

func backup(source, target string) error {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(target + suffix); err == nil {
			return fmt.Errorf("destination already exists: %s", target+suffix)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	source, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	open := func(path, mode string) (*sql.DB, error) {
		u := url.URL{Scheme: "file", Path: path}
		return sql.Open("sqlite3", u.String()+"?mode="+mode+"&_busy_timeout=1000")
	}
	src, err := open(source, "ro")
	if err != nil {
		return err
	}
	defer src.Close()
	sc, err := src.Conn(ctx)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer sc.Close()
	f, err := os.CreateTemp(filepath.Dir(target), ".tuc-backup-")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	defer func() {
		for _, s := range []string{"", "-wal", "-shm", "-journal"} {
			os.Remove(name + s)
		}
	}()
	dst, err := open(name, "rw")
	if err != nil {
		return err
	}
	defer dst.Close()
	dc, err := dst.Conn(ctx)
	if err != nil {
		return err
	}
	defer dc.Close()
	err = dc.Raw(func(d any) error {
		return sc.Raw(func(s any) error {
			b, err := d.(*sqlite3.SQLiteConn).Backup("main", s.(*sqlite3.SQLiteConn), "main")
			if err != nil {
				return err
			}
			done, err := b.Step(-1)
			finishErr := b.Finish()
			if err != nil {
				return err
			}
			if !done {
				return fmt.Errorf("SQLite backup did not complete (source busy)")
			}
			return finishErr
		})
	})
	if err != nil {
		return err
	}
	var check string
	if err := dc.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); err != nil {
		return err
	}
	if check != "ok" {
		return fmt.Errorf("snapshot failed quick_check: %s", check)
	}
	rows, err := dc.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	invalid := rows.Next()
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if invalid {
		return fmt.Errorf("snapshot failed foreign_key_check")
	}
	if _, err := dc.ExecContext(ctx, "PRAGMA journal_mode=DELETE"); err != nil {
		return err
	}
	if err := dc.Close(); err != nil {
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	snapshot, err := os.Open(name)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, snapshot); err != nil {
		return err
	}
	if err := snapshot.Sync(); err != nil {
		return err
	}
	if err := os.Link(name, target); err != nil {
		return fmt.Errorf("publish backup (destination must be new): %w", err)
	}
	dir, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return err
	}
	fmt.Printf("%s: sha256=%x\n", target, digest.Sum(nil))
	return nil
}
