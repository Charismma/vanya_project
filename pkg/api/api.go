package api

import (
	"Vanya/pkg/db"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	_ "github.com/tarantool/go-tarantool/v2/datetime"
	_ "github.com/tarantool/go-tarantool/v2/decimal"
	_ "github.com/tarantool/go-tarantool/v2/uuid"
)

type API struct {
	db     *db.Storage
	router *mux.Router
}

func New(db *db.Storage) *API {
	api := API{
		db: db,
	}
	api.router = mux.NewRouter()
	api.endpoints()
	return &api
}

func (api *API) endpoints() {
	api.router.HandleFunc("/register", api.registerHandler).Methods(http.MethodPost, http.MethodOptions)
	api.router.HandleFunc("/token", api.tokenHandler).Methods(http.MethodPost, http.MethodOptions)
	api.router.Handle("/kv/{key}", authMiddleware(http.HandlerFunc(api.upsertHandler))).Methods(http.MethodPut, http.MethodOptions)
	api.router.Handle("/kv/{key}", authMiddleware(http.HandlerFunc(api.getHandler))).Methods(http.MethodGet, http.MethodOptions)
	api.router.Handle("/kv/{key}", authMiddleware(http.HandlerFunc(api.deleteHandler))).Methods(http.MethodDelete, http.MethodOptions)

}

//api.router.Handle("/register", authMiddleware(http.HandlerFunc(api.registerHandler))).Methods(http.MethodPost, http.MethodOptions)

func (api *API) Router() *mux.Router {
	return api.router
}

func (api *API) registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") == "application/json" {
		var user db.User
		defer r.Body.Close()
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = api.db.NewSpace(user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "incorrect content-type", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (api *API) tokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") == "application/json" {
		var user db.User
		defer r.Body.Close()
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		token, exp, err := api.db.NewToken(user)
		log.Println(token, exp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

	} else {
		http.Error(w, "incorrect content-type", http.StatusBadRequest)
		return
	}
}
func (api *API) upsertHandler(w http.ResponseWriter, r *http.Request) {
	var value db.Value
	defer r.Body.Close()
	err := json.NewDecoder(r.Body).Decode(&value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	key := mux.Vars(r)["key"]
	user := r.Context().Value("user").(string)
	key, val, err := api.db.AddTuple(user, key, value.Value)
	log.Println("Обновление или добавление", key, user, val)
}
func (api *API) getHandler(w http.ResponseWriter, r *http.Request) {
	key := mux.Vars(r)["key"]
	user := r.Context().Value("user").(string)
	key, value, err := api.db.GetValue(user, key)
	log.Println("Получение значения по ключу", key, value, err)
}
func (api *API) deleteHandler(w http.ResponseWriter, r *http.Request) {
	key := mux.Vars(r)["key"]
	user := r.Context().Value("user")
	log.Println("Удаление значения по ключу", key, user)
}
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token_header := r.Header.Get("Authorization")
		if token_header == "" {
			http.Error(w, errors.New("нет заголовка с авторизацией").Error(), http.StatusUnauthorized)
		}
		token, exist := strings.CutPrefix(token_header, "Basic ")
		if !exist {
			http.Error(w, errors.New("нет basic в заголовке").Error(), http.StatusUnauthorized)
		}
		user, expires, ok, err := db.ValidToken(token)
		log.Println(user, expires)
		if err != nil {
			http.Error(w, errors.New("ошибка при проверке токена").Error(), http.StatusUnauthorized)
		}
		if !ok {
			http.Error(w, errors.New("токен не валиден").Error(), http.StatusUnauthorized)
		}
		log.Println("Токен Валиден, идем дальше")
		ctx := context.WithValue(context.Background(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
