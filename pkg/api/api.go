package api

import (
	"Vanya/pkg/db"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type user struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type API struct {
	db     db.Storage
	router *mux.Router
}

func New(db db.Storage) *API {
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
	api.router.Handle("/register", authMiddleware(http.HandlerFunc(api.upsertHandler))).Methods(http.MethodPut, http.MethodOptions)

}

//api.router.Handle("/register", authMiddleware(http.HandlerFunc(api.registerHandler))).Methods(http.MethodPost, http.MethodOptions)

func (api *API) Router() *mux.Router {
	return api.router
}

func (api *API) registerHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Регистрация пользователя")
}

func (api *API) tokenHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Получение токена")
}
func (api *API) upsertHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Обновление или добавление")
}
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Пришел новый запрос")

		next.ServeHTTP(w, r)
	})
}
