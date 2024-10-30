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
	"strings"
	"time"

	//"github.com/golang-jwt/jwt"
	"github.com/tarantool/go-tarantool/v2"
	"github.com/tarantool/go-tarantool/v2/crud"

	//_ "github.com/tarantool/go-tarantool/v2/crud"
	jwt "github.com/golang-jwt/jwt/v5"
	_ "github.com/tarantool/go-tarantool/v2/datetime"
	_ "github.com/tarantool/go-tarantool/v2/decimal"
	_ "github.com/tarantool/go-tarantool/v2/uuid"
)

// База данных
type Storage struct {
	db *tarantool.Connection
}

// //Пользователь
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// //Токен
type Token struct {
	Message    string `json:"message,omitempty"`
	Token      string `json:"token"`
	Expires_in int    `json:"expires_in"`
}

type Value struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint: structcheck,unused
	Value    string   `json:"value"`
}
type TupleUser struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint: structcheck,unused
	Login    string
	BucketId *uint64
	Password string
}

type Tuple struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint: structcheck,unused
	Key      string   `json:"key"`
	BucketId *uint64  `json:"-"`
	Value    string   `json:"value"`
}

type MyClaims struct {
	jwt.RegisteredClaims
	Username string `json:"sub"`
	Expires  int    `json:"exp"`
}

var (
	expires = 10000
	message = "Пользователь успешно зарегистрирован"
)

// Подключение к БД
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

// Добавление нового пользователя
func (s *Storage) NewUser(user User) (Token, error) {
	hash_pass := sha256.Sum256([]byte(user.Password))
	hashBase64 := base64.StdEncoding.EncodeToString(hash_pass[:])
	ret := crud.Result{}
	err := s.db.Do(
		crud.MakeInsertRequest("users").Tuple([]interface{}{user.Username, nil, hashBase64}),
	).GetTyped(&ret)
	if err != nil {
		return Token{}, err
	}
	result2, err := s.NewToken(user)
	if err != nil {
		return Token{}, err
	}
	result := Token{
		Message:    message,
		Token:      result2.Token,
		Expires_in: result2.Expires_in,
	}
	return result, nil
}

// Проверка существует ли пользователь
func (s *Storage) UserExist(user string) error {
	ret := crud.MakeResult(reflect.TypeOf(TupleUser{}))
	elem := crud.Condition{
		Operator: "=",
		Field:    "login",
		Value:    user,
	}
	uslov := []crud.Condition{}
	uslov = append(uslov, elem)
	err := s.db.Do(
		crud.MakeSelectRequest("users").Conditions(uslov),
	).GetTyped(&ret)
	if err != nil {
		return err
	}
	rows := ret.Rows.([]TupleUser)
	if len(rows) == 1 && rows[0].Login == user {
		return errors.New("409")
	}
	return nil
}

func (s *Storage) ValidUserPass(user User) (bool, error) {
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
		return false, err
	}
	rows := ret.Rows.([]TupleUser)
	hash_pass := sha256.Sum256([]byte(user.Password))
	hashBase64 := base64.StdEncoding.EncodeToString(hash_pass[:])
	if len(rows) == 1 && rows[0].Login == user.Username && rows[0].Password == hashBase64 {
		return true, nil
	}
	return false, nil
}

// Выдача нового токена
func (s *Storage) NewToken(user User) (Token, error) {
	//генерируем токен jwt
	token, exp, err := generateToken(user.Username)
	if err != nil {
		return Token{}, err
	}
	result := Token{
		Token:      token,
		Expires_in: exp,
	}
	return result, err
}

// Генерация токена
func generateToken(username string) (string, int, error) {
	jwtSecretKey, exists := os.LookupEnv("JWT_PASS")
	if !exists {
		return "", 0, errors.New("Ошибка")
	}
	jwtSecretKey2 := []byte(jwtSecretKey)
	exp := time.Now().Add(time.Second * time.Duration(expires)).Unix()
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

// Проверка токена
func ValidToken(token string) (MyClaims, bool, error) {
	keyFunc := func(t *jwt.Token) (interface{}, error) {
		// Проверяем, что используется ожидаемый метод подписи
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("неожиданный метод подписи: %v", t.Header["alg"])
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
		return MyClaims{}, false, err
	}
	if !parsedToken.Valid {
		return MyClaims{}, false, errors.New("токен не валиден")
	}
	return *claims, true, nil

}

// //Добавление кортежа с токеном
func (s *Storage) AddToken(user string, result Token) error {
	ret := crud.Result{}
	err := s.db.Do(
		crud.MakeUpsertRequest("tokens").Tuple([]interface{}{user, nil, result.Token, result.Expires_in}),
	).GetTyped(&ret)
	if err != nil {
		return err
	}
	return nil
}

//Получение значения по ключу

func (s *Storage) GetValue(user string, key string) (Tuple, error) {
	ret := crud.MakeResult(reflect.TypeOf(Tuple{}))
	key_user := key + "_" + user
	elem := crud.Condition{
		Operator: "=",
		Field:    "key",
		Value:    key_user,
	}
	uslov := []crud.Condition{}
	uslov = append(uslov, elem)
	err := s.db.Do(
		crud.MakeSelectRequest("data").Conditions(uslov),
	).GetTyped(&ret)
	if err != nil {
		return Tuple{}, err
	}
	rows := ret.Rows.([]Tuple)
	suffix := "_" + user
	key_norm, exist := strings.CutSuffix(rows[0].Key, suffix)
	rows[0].Key = key_norm
	if !exist {
		return Tuple{}, err
	}
	if len(rows) == 1 {
		return rows[0], nil
	} else {
		return Tuple{}, errors.New("no value")
	}
}

// Добавление нового кортежа с ключом и значением
func (s *Storage) AddTuple(user string, key string, value string) error {
	ret := crud.MakeResult(reflect.TypeOf(Tuple{}))
	key_user := key + "_" + user
	err := s.db.Do(
		crud.MakeUpsertRequest("data").Tuple([]interface{}{key_user, nil, value})).GetTyped(&ret)
	if err != nil {
		return err
	}
	return nil
}
