package main

import (
	"Vanya/pkg/api"
	"Vanya/pkg/db"
	"log"
	"net/http"
)

type user struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type server struct {
	db  *db.Storage
	api *api.API
}

func main() {
	var srv server
	db, err := db.New()
	if err != nil {
		log.Println(err)
		return
	}
	srv.db = db
	srv.api = api.New(*srv.db)
	log.Println("Запуск сервера на порту 8081")
	err = http.ListenAndServe(":8081", srv.api.Router())
	if err != nil {
		log.Fatal(err)
	}

}