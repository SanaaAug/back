package main

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
)

var db *sql.DB

func initDB() {
	psql_str := "host=localhost port=5432 user=postgres password=0819 dbname=project1 sslmode=disable"
	var err error
	db, err = sql.Open("postgres", psql_str)
	if err != nil {
		log.Fatalf("DB open failed: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("DB connection failed: %v", err)
	}
}

func closeDB() {
	err := db.Close()
	if err != nil {

	}
}

func addUser(u *User) (int, string, string) {
	var id int

	if u.Username == "" {
		u.Username = u.Firstname + " " + u.Lastname
	}

	err := db.QueryRow("insert into users (firstname, lastname, username, email, profile_image, password_hash, google_id)values($1, $2, $3, $4, $5,$6, $7) returning id", u.Firstname, u.Lastname, u.Username, u.Email, u.ImageByte, u.Password, u.GoogleID).Scan(&id)
	if err != nil {
		log.Println(err.Error())
		return 0, "", ""
	}
	session_id_month := addSession(id, 2)
	session_id_day := addSession(id, 1)
	log.Println("add user worked")
	return id, session_id_day, session_id_month
}

func getUserId(email string) int {
	id := 0
	err := db.QueryRow("select id from users where email=$1", email).Scan(&id)
	if err != nil {
		log.Println(err.Error())
	}

	return id
}

func addSession(user_id int, session_type int) string {
	session_id, err := generateSessionId()
	if err != nil {

	}
	if session_type == 1 {
		_, err = db.Exec("insert into sessions (session_id, user_id, authenticated, session_type) values($1, $2, $3, $4)", session_id, user_id, true, 1)
	} else {
		expires_at := time.Now().Add(time.Hour * 24 * 30)
		_, err = db.Exec("insert into sessions (session_id, user_id, authenticated, expires_at ,session_type) values($1, $2, $3, $4, $5)", session_id, user_id, true, expires_at, 2)
	}
	if err != nil {
		log.Println(err.Error())
		return ""
	}

	return session_id

}

func getUser(user_id int) (*User, error) {
	var user User
	err := db.QueryRow("select id, firstname, lastname, username, email, profile_image from users where id = $1", user_id).Scan(&user.ID, &user.Firstname, &user.Lastname, &user.Username, &user.Email, &user.ImageByte)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func getSessionForUserID(id int, s_type int) string {
	var s_id string
	if s_type == 1 {
		err := db.QueryRow("select session_id from sessions where user_id = $1 and authenticated=true and session_type", id, s_type).Scan(&s_id)
		if err != nil {
			return ""
		}
	} else {
		err := db.QueryRow("select session_id from sessions where user_id = $1 and authenticated=true and session_type", id, s_type).Scan(&s_id)
		if err != nil {
			return ""
		}
	}

	return s_id

}

func validateUser(email string, password string) (*User, error) {
	var user User
	err := db.QueryRow("select firstname, lastname, username, email, profile_image from users where email = $1 and password_hash = $2", email, password).Scan(&user.Firstname, &user.Lastname, &user.Username, &user.Email, &user.ImageByte)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func change_password(email string, password string, newpass string) (bool, error) {
	var id int
	err := db.QueryRow("update users set password_hash=$1 where email=$2 and password_hash=$3 returning id", newpass, email, password).Scan(&id)
	if err != nil {
		log.Fatal(err.Error())
		return false, nil
	}
	deleteAllSessionOfUser(id)
	err = fmt.Errorf("no rows affected")
	return false, err
}

func deleteUser(email string, password string) {
	res, err := db.Exec("delete from users where email = $1 and password_hash = $2", email, password)
	if err != nil {
		log.Fatal(err.Error())
		return
	}
	rows, _ := res.RowsAffected()
	log.Println(rows)
}

func deleteAllSessionOfUser(user_id int) {
	res, err := db.Exec("delete from sessions where user_id = $1", user_id)
	if err != nil {
		log.Fatal(err.Error())
		return
	}
	rows, _ := res.RowsAffected()
	log.Println(rows)
}

func deleteSession(session_id string) {
	res, err := db.Exec("delete from sessions where session_id = $1", session_id)
	if err != nil {
		log.Fatal(err.Error())
		return
	}
	rows, _ := res.RowsAffected()
	log.Println(rows)

}

func getSession(session_id string) (s *SessionData) {

	session := SessionData{}
	err := db.QueryRow("select user_id, authenticated, device_id, created_at, expires_at from sessions where session_id = $1", session_id).Scan(&session.UserID, &session.Authenticated, &session.DeviceID, &session.CreatedAt, &session.ExpiresAt)
	if err != nil {
		log.Println("get session error")
	}
	return &session
}

func validateUserByEmail(email string) bool {
	var exist bool
	err := db.QueryRow("select exists(select 1 from users where email = $1)", email).Scan(&exist)
	if err != nil {

		log.Println("get valitade user by email error")
	}

	if exist {
		return true
	}
	return false
}

func validateUserByPhone(number string) bool {
	var exist bool
	err := db.QueryRow("select exists(select 1 from users where phone_number = $1)", number).Scan(&exist)
	if err != nil {

		log.Println("get valitade user by email error")
	}

	if exist {
		return true
	}
	return false
}
