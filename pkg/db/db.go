package db

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"time"

	"github.com/tarantool/go-tarantool/v2"
	"github.com/tarantool/go-tarantool/v2/crud"

	//_ "github.com/tarantool/go-tarantool/v2/crud"
	jwt "github.com/golang-jwt/jwt/v5"
	_ "github.com/tarantool/go-tarantool/v2/datetime"
	_ "github.com/tarantool/go-tarantool/v2/decimal"
	_ "github.com/tarantool/go-tarantool/v2/uuid"
)

type Storage struct {
	db *tarantool.Connection
}
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type Token struct {
	Token      string `json:"token"`
	Expires_in int    `json:"expires_in"`
}
type Value struct {
	Value string `json:"value"`
}
type TupleUser struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint: structcheck,unused
	Login    string
	BucketId *uint64
	Password string
}
type Tuple struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint: structcheck,unused
	Key      string
	BucketId *uint64
	Value    string
}
type MyClaims struct {
	jwt.RegisteredClaims
	Username string `json:"sub"`
	Expires  int    `json:"exp"`
}

var (
	expires = 72
)

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

func (s *Storage) NewSpace(user User) error {
	hash_pass := sha256.Sum256([]byte(user.Password))
	hashBase64 := base64.StdEncoding.EncodeToString(hash_pass[:])
	ret := crud.Result{}
	err := s.db.Do(
		crud.MakeInsertRequest("users").Tuple([]interface{}{user.Username, nil, hashBase64}),
	).GetTyped(&ret)
	//log.Println(ret.Rows, " ", ret.Metadata)
	if err != nil {
		return err
	}
	_, err = s.db.Do(
		tarantool.NewEvalRequest(fmt.Sprintf("box.schema.create_space('%s',{format = {{name='key',type='string'},{name='bucket_id',type='unsigned'},{name='value', type='string'}}}) box.space.%s:create_index('key',{parts={'key'}})", user.Username, user.Username)),
	).Get()
	if err != nil {
		return err
	}
	return nil
}
func (s *Storage) NewToken(user User) (string, int, error) {
	ret := crud.MakeResult(reflect.TypeOf(TupleUser{}))
	elem := crud.Condition{
		Operator: "=",
		Field:    "login",
		Value:    user.Username,
	}
	uslov := []crud.Condition{}
	uslov = append(uslov, elem)
	err := s.db.Do(
		crud.MakeSelectRequest("users").Conditions(uslov),
	).GetTyped(&ret)
	if err != nil {
		return "", 0, err
	}
	rows := ret.Rows.([]TupleUser)
	hash_pass := sha256.Sum256([]byte(user.Password))
	hashBase64 := base64.StdEncoding.EncodeToString(hash_pass[:])
	if len(rows) == 1 && rows[0].Login == user.Username && rows[0].Password == hashBase64 {
		//генерируем токен jwt
		token, exp, err := generateToken(rows[0].Login)
		if err != nil {
			return "", 0, err
		}
		// log.Println("Генерация токена", token)
		// log.Println("Генерация токена", exp)
		return token, exp, err
	} else {
		return "", 0, errors.New("login or password incorrect")
	}
}

func generateToken(username string) (string, int, error) {
	jwtSecretKey, exists := os.LookupEnv("JWT_PASS")
	if !exists {
		return "", 0, errors.New("Ошибка")
	}
	jwtSecretKey2 := []byte(jwtSecretKey)
	exp := time.Now().Add(time.Hour * time.Duration(expires)).Unix()
	payload := jwt.MapClaims{
		"sub": username,
		"exp": exp,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	t, err := token.SignedString(jwtSecretKey2)
	if err != nil {
		return "", 0, err
	}
	exp2 := int(exp)
	return t, exp2, nil
}

func ValidToken(token string) (string, int, bool, error) {
	keyFunc := func(t *jwt.Token) (interface{}, error) {
		// Проверяем, что используется ожидаемый метод подписи
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Неожиданный метод подписи: %v", t.Header["alg"])
		}
		jwtSecretKey, exists := os.LookupEnv("JWT_PASS")
		if !exists {
			return nil, errors.New("ошибка")
		}
		jwtSecretKey2 := []byte(jwtSecretKey)
		// Возвращаем секретный ключ для jwt токена, в формате []byte, совпадающий с ключом, использованным для подписи ранее
		return jwtSecretKey2, nil
	}
	claims := &MyClaims{}
	parsedToken, err := jwt.ParseWithClaims(token, claims, keyFunc)
	if err != nil {
		return "", 0, false, err
	}
	if !parsedToken.Valid {
		return "", 0, false, errors.New("не валиден")
	}
	log.Println(claims.Expires, claims.Username)
	return claims.Username, claims.Expires, true, nil

}
func (s *Storage) AddToken(user string, token string, expires int) error {
	ret := crud.Result{}
	err := s.db.Do(
		crud.MakeInsertRequest("tokens").Tuple([]interface{}{user, nil, token, expires}),
	).GetTyped(&ret)
	if err != nil {
		return err
	}
	return nil
}

func (s *Storage) GetValue(user string, key string) (string, string, error) {
	ret := crud.MakeResult(reflect.TypeOf(Tuple{}))
	elem := crud.Condition{
		Operator: "=",
		Field:    "key",
		Value:    key,
	}
	uslov := []crud.Condition{}
	uslov = append(uslov, elem)
	err := s.db.Do(
		crud.MakeSelectRequest(user).Conditions(uslov),
	).GetTyped(&ret)
	if err != nil {
		return "", "", err
	}
	rows := ret.Rows.([]Tuple)
	if len(rows) == 1 {
		return rows[0].Key, rows[0].Value, nil
	} else {
		return "", "", errors.New("no value")
	}
}
func (s *Storage) AddTuple(user string, key string, value string) (string, string, error) {
	ret := crud.MakeResult(reflect.TypeOf(Tuple{}))
	err := s.db.Do(
		crud.MakeUpsertRequest(user).Tuple([]interface{}{key, nil, value})).GetTyped(&ret)
	if err != nil {
		return "", "", err
	}
	rows := ret.Rows.([]Tuple)
	if len(rows) == 1 {
		return rows[0].Key, rows[0].Value, nil
	} else {
		return "", "", errors.New("no value")
	}
}

// spaceName := "new_space"

// log.Println(ret.Rows)
// err := api.db.Do(
// 	crud.MakeGetRequest("users").Key([]interface{}{"l"}),
// ).GetTyped(&ret)
// _, err = api.db.Do(
// 	tarantool.NewEvalRequest(fmt.Sprintf("box.schema.space.create('%s')", spaceName)),
// ).Get()
// data, err := api.db.Do(
// 	tarantool.NewSelectRequest("users").Index("login").Limit(1).Iterator(tarantool.IterEq).Key([]interface{}{"l"}),
// ).Get()
