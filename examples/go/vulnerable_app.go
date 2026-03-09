package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os/exec"
)

func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	targetURL := r.URL.Query().Get("url")
	command := r.URL.Query().Get("cmd")

	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", user)
	db.Query(query)

	http.Get(targetURL)
	exec.Command("sh", "-c", command).Output()

	token := fmt.Sprintf("%d", rand.Int())
	hash := md5.Sum([]byte(user + token))

	w.Write([]byte("<div>" + user + "</div>"))
	fmt.Println(hash)
}
