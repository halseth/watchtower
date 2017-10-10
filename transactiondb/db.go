package transactiondb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/boltdb/bolt"
	"github.com/halseth/watchtower/wtwire"
)

const (
	dbName           = "txdb.db"
	dbFilePermission = 0600
)

var (
	txBucket      = []byte("encrypted-transactions")
	sessionBucket = []byte("session-info")

	// Big endian is the preferred byte order, due to cursor scans over
	// integer keys iterating in order.
	byteOrder = binary.BigEndian
)

type DB struct {
	*bolt.DB
	dbPath string
}

func Open(dbPath string) (*DB, error) {
	path := filepath.Join(dbPath, dbName)

	if !fileExists(path) {
		if err := createDB(dbPath); err != nil {
			return nil, err
		}
	}

	bdb, err := bolt.Open(path, dbFilePermission, nil)
	if err != nil {
		return nil, err
	}

	db := &DB{
		DB:     bdb,
		dbPath: dbPath,
	}

	return db, nil
}

func (d *DB) InsertSessionInfo(info *wtwire.SessionInfo) error {
	err := d.Batch(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(sessionBucket)
		if err != nil {
			return err
		}
		var key [8]byte
		byteOrder.PutUint64(key[:], info.SessionID)

		var b bytes.Buffer
		if err := info.Encode(&b, 0); err != nil {
			return err
		}
		return bucket.Put(key[:], b.Bytes())
	})
	if err != nil {
		return err
	}
	return nil
}

var ErrNotFound = errors.New("not found in db")

func (d *DB) GetSessionInfo(sessionID uint64) (*wtwire.SessionInfo, error) {
	var key [8]byte
	byteOrder.PutUint64(key[:], sessionID)

	var info *wtwire.SessionInfo

	if err := d.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(sessionBucket)
		if bucket == nil {
			return ErrNotFound
		}

		i := bucket.Get(key[:])
		if i == nil {
			return ErrNotFound
		}

		r := bytes.NewReader(i)

		info = &wtwire.SessionInfo{}
		if err := info.Decode(r, 0); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return info, nil
}

func (d *DB) InsertTransaction(blob *wtwire.StateUpdate) error {
	err := d.Batch(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(txBucket)
		if err != nil {
			return err
		}
		var b bytes.Buffer

		var id [8]byte
		byteOrder.PutUint64(id[:], blob.SessionID)
		if _, err := b.Write(id[:]); err != nil {
			return err
		}
		if _, err := b.Write(blob.EncryptedBlob[:]); err != nil {
			return err
		}
		return bucket.Put(blob.TxIDPrefix[:], b.Bytes())
	})
	if err != nil {
		return err
	}
	return nil
}

func (d *DB) ListEntries() error {
	return d.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(txBucket)
		if bucket == nil {
			return nil
		}
		bucket.ForEach(func(k, v []byte) error {
			fmt.Printf("key=%s, value=%s\n", k, v)
			return nil
		})
		return nil
	})
}

func (d *DB) FindMatches(prefixes [][16]byte) ([]*wtwire.StateUpdate, error) {
	var matches []*wtwire.StateUpdate
	err := d.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(txBucket)
		if bucket == nil {
			return nil
		}
		for _, p := range prefixes {
			v := bucket.Get(p[:])
			if v != nil {
				sessionID := byteOrder.Uint64(v[:8])
				var blob [112]byte
				copy(blob[:], v[8:])
				matches = append(matches, &wtwire.StateUpdate{
					SessionID:     sessionID,
					TxIDPrefix:    p,
					EncryptedBlob: blob,
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return matches, nil
}

func (d *DB) Wipe() error {
	return d.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket(txBucket)
		if err != nil && err != bolt.ErrBucketNotFound {
			return err
		}

		return nil
	})
}

func createDB(dbPath string) error {
	if !fileExists(dbPath) {
		if err := os.MkdirAll(dbPath, 0700); err != nil {
			return err
		}
	}

	path := filepath.Join(dbPath, dbName)
	bdb, err := bolt.Open(path, dbFilePermission, nil)
	if err != nil {
		return err
	}

	if err != nil {
		return fmt.Errorf("unable to create new db")
	}

	return bdb.Close()
}

// fileExists returns true if the file exists, and false otherwise.
func fileExists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}
