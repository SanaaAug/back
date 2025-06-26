package main

import (
	"database/sql"
	"time"
)

type Data struct {
	Title string
}

type Account struct {
	ID          int    `json:"id"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	NewPassword string `json:"newpass"`
}

type SessionData struct {
	UserID        int
	Authenticated bool
	Username      string
	Email         string
	DeviceID      sql.NullInt32
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

type GoogleUserInfo struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	Given_name  string `json:"given_name"`
	Family_name string `json:"family_name"`
	PictureURL  string `json:"picture"`
}

type FacebookUserInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Picture struct {
		Data struct {
			URL string `json:"url"`
		} `json:"data"`
	} `json:"picture"`
}

type User struct {
	ID            int    `json:"id"`
	Firstname     string `json:"firstname"`
	Lastname      string `json:"lastname"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	PhoneNumber   string `json:"phonenumber"`
	Address       string `json:"address"`
	ImageURL      string `json:"pictureurl"`
	ImageByte     []byte `json:"picture"`
	Authenticated bool   `json:"authenticated"`
	Password      string
	GoogleID      string `json:"google_id"`
	FacebookID    string `json:"facebook_id"`
}
