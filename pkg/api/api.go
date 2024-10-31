package api

import (
	"Vanya/pkg/db"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/tarantool/go-tarantool/v2/datetime"
	_ "github.com/tarantool/go-tarantool/v2/decimal"
	_ "github.com/tarantool/go-tarantool/v2/uuid"
)

// API
type API struct {
	db     *db.Storage
	router *mux.Router
}

// Конструктор API
func New(db *db.Storage) *API {
	api := API{
		db: db,
	}
	api.router = mux.NewRouter()
	api.endpoints()
	return &api
}

type ContextValueKey string

const IdentityKey ContextValueKey = "user"

type ContextValueKey_Key string

const IdentityKey_Key ContextValueKey = "key"

// endpoints прложения
func (api *API) endpoints() {
	api.router.HandleFunc("/register", api.registerHandler).Methods(http.MethodPost, http.MethodOptions)
	api.router.HandleFunc("/token", api.tokenHandler).Methods(http.MethodPost, http.MethodOptions)
	api.router.Handle("/kv/{key}", authMiddleware(http.HandlerFunc(api.upsertHandler))).Methods(http.MethodPut, http.MethodOptions)
	api.router.Handle("/kv/{key}", authMiddleware(http.HandlerFunc(api.getHandler))).Methods(http.MethodGet, http.MethodOptions)
	api.router.Handle("/kv/{key}", authMiddleware(http.HandlerFunc(api.deleteHandler))).Methods(http.MethodDelete, http.MethodOptions)

}

// Роутер
func (api *API) Router() *mux.Router {
	return api.router
}

// Регистрация нового пользователя и выдача ему токена
func (api *API) registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") == "application/json" {
		var user db.User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		if user.Username == "" || user.Password == "" {
			http.Error(w, errors.New("отсутвует пользователь или пароль").Error(), http.StatusBadRequest)
			return
		}
		err = api.db.UserExist(user.Username)
		if err != nil {
			if err.Error() == "409" {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		result, err := api.db.NewUser(user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = api.db.AddToken(user.Username, result)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(result)
	} else {
		http.Error(w, "incorrect content-type", http.StatusBadRequest)
		return
	}
}

// //Получение нового токена
func (api *API) tokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") == "application/json" {
		var user db.User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		if user.Username == "" || user.Password == "" {
			http.Error(w, errors.New("отсутвует пользователь или пароль").Error(), http.StatusBadRequest)
			return
		}
		exist, err := api.db.ValidUserPass(user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !exist {
			http.Error(w, errors.New("неправильное имя пользователя или пароль").Error(), http.StatusUnauthorized)
			return
		}
		result, err := api.db.NewToken(user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = api.db.AddToken(user.Username, result)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(result)
	} else {
		http.Error(w, "incorrect content-type", http.StatusBadRequest)
		return
	}
}

// Вставка или обновление кортеда по ключу
func (api *API) upsertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") == "application/json" {
		var value db.Value
		err := json.NewDecoder(r.Body).Decode(&value)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		if value.Value == "" {
			http.Error(w, errors.New("отсутвует значение").Error(), http.StatusBadRequest)
			return
		}
		key := r.Context().Value(IdentityKey_Key).(string)
		if key == "" {
			http.Error(w, errors.New("пустое значение ключа").Error(), http.StatusBadRequest)
			return
		}
		if len(value.Value) > 5120 {
			http.Error(w, errors.New("value превышает 5 КБ").Error(), http.StatusBadRequest)
			return
		}
		user := r.Context().Value(IdentityKey).(string)
		err = api.db.AddTuple(user, key, value.Value)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	} else {
		http.Error(w, "incorrect content-type", http.StatusBadRequest)
		return
	}
}

// Получение кортежа по ключу
func (api *API) getHandler(w http.ResponseWriter, r *http.Request) {
	key := r.Context().Value(IdentityKey_Key).(string)
	if key == "" {
		http.Error(w, errors.New("пустое значение ключа").Error(), http.StatusBadRequest)
		return
	}
	user := r.Context().Value(IdentityKey).(string)
	tuple, err := api.db.GetValue(user, key)
	if err != nil {
		if err.Error() == "no value" {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tuple)
}

// Удаление кортежа по ключу
func (api *API) deleteHandler(w http.ResponseWriter, r *http.Request) {
	key := r.Context().Value(IdentityKey_Key).(string)
	if key == "" {
		http.Error(w, errors.New("пустое значение ключа").Error(), http.StatusBadRequest)
		return
	}
	user := r.Context().Value(IdentityKey).(string)
	err := api.db.DeleteTuple(user, key)
	if err != nil {
		if err.Error() == "no value" {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Middleware для авторизации пользователя
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token_header := r.Header.Get("Authorization")
		if token_header == "" {
			http.Error(w, errors.New("отсутствует заголовок с авторизацией").Error(), http.StatusUnauthorized)
			return
		}
		token, exist := strings.CutPrefix(token_header, "Basic ")
		if !exist {
			http.Error(w, errors.New("отсутствует Basic в заголовке").Error(), http.StatusUnauthorized)
			return
		}
		claims, ok, err := db.ValidToken(token)
		if err != nil {
			http.Error(w, errors.New("ошибка при проверке токена").Error(), http.StatusUnauthorized)
			return
		}
		if !ok {
			http.Error(w, errors.New("токен не валиден").Error(), http.StatusUnauthorized)
			return
		}
		now := int(time.Now().Unix())
		if now > claims.Expires {
			http.Error(w, errors.New("действие токена закончилось").Error(), http.StatusUnauthorized)
			return
		}
		key := mux.Vars(r)["key"]
		if key == "" {
			http.Error(w, errors.New("пустое значение ключа").Error(), http.StatusBadRequest)
			return
		}
		if len(key) > 1024 {
			http.Error(w, errors.New("key превышает 1 КБ").Error(), http.StatusBadRequest)
			return
		}
		ctx := context.WithValue(context.Background(), IdentityKey, claims.Username)
		ctx2 := context.WithValue(ctx, IdentityKey_Key, key)
		next.ServeHTTP(w, r.WithContext(ctx2))
	})
}
