package db

import (
	"context"
	"log"
	"time"

	"github.com/tarantool/go-tarantool/v2"
	_ "github.com/tarantool/go-tarantool/v2/datetime"
	_ "github.com/tarantool/go-tarantool/v2/decimal"
	_ "github.com/tarantool/go-tarantool/v2/uuid"
)

type Storage struct {
	db *tarantool.Connection
}

func New() (*Storage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	dialer := tarantool.NetDialer{
		Address:  "192.168.56.101:3301",
		User:     "sampleuser",
		Password: "123456",
	}
	opts := tarantool.Opts{
		Timeout: time.Second,
	}
	db, err := tarantool.Connect(ctx, dialer, opts)
	if err != nil {
		log.Println("Connection refused:", err)
		return nil, err
	}
	s := Storage{
		db: db,
	}
	return &s, nil
}
