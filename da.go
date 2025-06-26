package main

import (
	"database/sql"
	"log"
	"strconv"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/oauth2"
)

var db *sql.DB

func initDB() {
	psql_str := "postgresql://user1:jN0jzQCpjlPKULNBorx6DD3uldVzQbmG@dpg-d1dsfqqdbo4c73e8sdg0-a/database1_kakl"
	var err error
	db, err = sql.Open("postgres", psql_str)
	if err != nil {
		log.Fatal("[ERROR] Database open failed: " + err.Error())
	}
	if err := db.Ping(); err != nil {
		log.Fatal("[ERROR] Database connection failed: ", err.Error())
	} else {
		log.Println("[INFO] Connected to database")
	}
}

func closeDB() {
	err := db.Close()
	if err != nil {
		log.Fatal("[ERROR] Database close failed: " + err.Error())
	}
}

func addUser(u *User, origin int) (int, string, string) {
	var id int

	if u.Username == "" {
		u.Username = u.Firstname + " " + u.Lastname
	}
	var err error
	switch origin {
	case 0:
		err = db.QueryRow("insert into users (firstname, lastname, username, email, profile_image, password_hash)values($1, $2, $3, $4, $5, $6) returning id", u.Firstname, u.Lastname, u.Username, u.Email, u.ImageByte, u.Password).Scan(&id)
	case 1:
		u.Username += " (google)"
		err = db.QueryRow("insert into users (firstname, lastname, username, email, profile_image, password_hash, google_id, profile_image_url)values($1, $2, $3, $4, $5,$6, $7, $8) returning id", u.Firstname, u.Lastname, u.Username, u.Email, u.ImageByte, u.Password, u.GoogleID, u.ImageURL).Scan(&id)
	case 2:
		u.Username += " (facebook)"
		err = db.QueryRow("insert into users (firstname, lastname, username, email, profile_image, password_hash, facebook_id, profile_image_url)values($1, $2, $3, $4, $5,$6, $7, $8) returning id", u.Firstname, u.Lastname, u.Username, u.Email, u.ImageByte, u.Password, u.FacebookID, u.ImageURL).Scan(&id)
	}

	if err != nil {
		log.Println("[ERROR] Creating account with email: " + u.Email + " failed: " + err.Error())
		return 0, "", ""
	} else {
		log.Println("[INFO] Created account with email: " + u.Email + " and id: " + strconv.Itoa(id))
	}
	session_id_month := addSession(id, 2)
	session_id_day := addSession(id, 1)
	return id, session_id_day, session_id_month
}

func getUserId(email string) int {
	id := 0
	err := db.QueryRow("select id from users where email=$1", email).Scan(&id)
	if err != nil {
		log.Println("[ERROR] Failed to get user id with email: " + email + "failed: " + err.Error())
		return 0
	}
	log.Println("[INFO] Got user id with email: " + email)
	return id
}

func addSession(user_id int, session_type int) string {
	session_id, err := generateSessionId()
	if err != nil {
		log.Println("[ERROR] Failed to generate session_id.")
		return ""
	}
	if session_type == 1 {
		_, err = db.Exec("insert into sessions (session_id, user_id, authenticated, session_type) values($1, $2, $3, $4)", session_id, user_id, true, 1)

	} else {
		expires_at := time.Now().Add(time.Hour * 24 * 30)
		_, err = db.Exec("insert into sessions (session_id, user_id, authenticated, expires_at ,session_type) values($1, $2, $3, $4, $5)", session_id, user_id, true, expires_at, 2)
	}
	if err != nil {
		log.Println("[ERROR] Failed to create session for user with id: " + strconv.Itoa(user_id) + " type: " + strconv.Itoa(session_type) + "failed: " + err.Error())
		return ""
	}
	log.Println("[INFO] Created session for user with id: " + strconv.Itoa(user_id) + " type: " + strconv.Itoa(session_type))
	return session_id

}

func getUser(user_id int) (*User, error) {
	var user User
	err := db.QueryRow("select id, firstname, lastname, username, email, profile_image, profile_image_url from users where id = $1", user_id).Scan(&user.ID, &user.Firstname, &user.Lastname, &user.Username, &user.Email, &user.ImageByte, &user.ImageURL)
	if err != nil {
		log.Println("[ERROR] Failed to get information for user with id: " + strconv.Itoa(user_id) + "failed: " + err.Error())
		return nil, err
	}
	log.Println("[INFO] Got user information with id: " + strconv.Itoa(user_id))
	return &user, nil
}

func getSessionForUserID(id int, s_type int) string {
	var s_id string
	var err error
	if s_type == 1 {
		err = db.QueryRow("select session_id from sessions where user_id = $1 and authenticated=true and session_type", id, s_type).Scan(&s_id)
	} else {
		err = db.QueryRow("select session_id from sessions where user_id = $1 and authenticated=true and session_type", id, s_type).Scan(&s_id)

	}
	if err != nil {
		log.Println("[ERROR] Failed to get session_id with id: " + strconv.Itoa(id) + " type: " + strconv.Itoa(s_type) + "failed: " + err.Error())
		return ""
	}
	log.Println("[INFO] Got session_id with id: " + strconv.Itoa(id) + " type: " + strconv.Itoa(s_type))
	return s_id

}

func validateUser(email string, password string) (*User, error) {
	var user User
	err := db.QueryRow("select firstname, lastname, username, email, profile_image from users where email = $1 and password_hash = $2", email, password).Scan(&user.Firstname, &user.Lastname, &user.Username, &user.Email, &user.ImageByte)
	if err != nil {
		log.Println("[ERROR] Failed to validate user with email: " + email + "failed: " + err.Error())
		return nil, err
	}
	log.Println("[INFO] Validated user with email: " + email)
	return &user, nil
}

func change_password(email string, password string, newpass string) (bool, error) {
	var id int
	err := db.QueryRow("update users set password_hash=$1 where email=$2 and password_hash=$3 returning id", newpass, email, password).Scan(&id)
	if err != nil {
		log.Println("[ERROR] Failed to update user password with email: " + email + "failed: " + err.Error())
		return false, nil
	}
	log.Println("[INFO] Updated user password with email: " + email)
	editAllSessionOfUser(id)
	return false, err
}

func deleteUser(email string, password string) {
	_, err := db.Exec("delete from users where email = $1 and password_hash = $2", email, password)
	if err != nil {
		log.Println("[ERROR] Failed to delete user with email: " + email + "failed: " + err.Error())
		return
	}
	log.Println("[INFO] Deleted user with email: " + email)
}

func editAllSessionOfUser(user_id int) {
	_, err := db.Exec("update sessions set expires_at = NOW() where user_id = $1", user_id)
	if err != nil {
		log.Println("[ERROR] Failed to delete sessions of user with id: " + strconv.Itoa(user_id) + "failed: " + err.Error())
		return
	}
	log.Println("[INFO] Deleted all sessions of user with id: " + strconv.Itoa(user_id))
}

func editSession(session_id string) {
	_, err := db.Exec("update sessions set expires_at = NOW() where session_id = $1", session_id)
	if err != nil {
		log.Println("[ERROR] Failed to delete session with session_id: " + session_id + "failed: " + err.Error())
		return
	}
	log.Println("[INFO] Deleted session with session_id: " + session_id)
}

func getSession(session_id string) (s *SessionData) {

	session := SessionData{}
	err := db.QueryRow("select user_id, authenticated, device_id, created_at, expires_at from sessions where session_id = $1", session_id).Scan(&session.UserID, &session.Authenticated, &session.DeviceID, &session.CreatedAt, &session.ExpiresAt)
	if err != nil {
		log.Println("[ERROR] Failed to get session info with session_id: " + session_id + "failed: " + err.Error())
		return nil
	}
	log.Println("[INFO] Got session info with session_id: " + session_id)
	return &session
}

func validateUserByEmail(email string) bool {
	var exist bool
	err := db.QueryRow("select exists(select 1 from users where email = $1)", email).Scan(&exist)
	if err != nil {
		log.Println("[ERROR] Failed to validate user with email: " + email + "failed: " + err.Error())
		return false
	}
	log.Println("[INFO] Tried to validate user with email: " + email)
	return exist
}

func validateUserByPhone(number string) bool {
	var exist bool
	err := db.QueryRow("select exists(select 1 from users where phone_number = $1)", number).Scan(&exist)
	if err != nil {
		log.Println("[ERROR] Failed to validate user with phone number: " + number + "failed: " + err.Error())
	}
	log.Println("[INFO] Tried to validate user with phone number: " + number)
	return exist
}

func save_token(user_id int, t *oauth2.Token, t_type int) {
	var err error
	if t_type == 1 {
		_, err = db.Exec("insert into tokens (user_id, google_access_token, google_access_token_expiry, google_refresh_token) values ($1, $2, $3, $4)", user_id, t.AccessToken, t.Expiry, t.RefreshToken)
	} else {
		_, err = db.Exec("insert into tokens (user_id, facebook_access_token, facebook_access_token_expiry, facebook_refresh_token) values ($1, $2, $3, $4)", user_id, t.AccessToken, t.Expiry, t.RefreshToken)
	}
	if err != nil {
		log.Println("[ERROR] Failed to save tokens with user id: " + strconv.Itoa(user_id) + "failed: " + err.Error())
	}
}
