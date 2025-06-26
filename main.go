package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/cors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
)

var (
	googleConfig   *oauth2.Config
	facebookConfig *oauth2.Config
)

const Google_ClientID = "678423924487-embq50bfe7q0flq7fc5cbpire8oltq4i.apps.googleusercontent.com"
const Google_ClientSecret = "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"
const Facebook_ClientID = "1000577802291152"
const Facebook_ClientSecret = "57c825c2feecdbc89e1cac69893bd053"

const sessionCookieNameDay = "session_token_day"
const sessionDurationDay = time.Hour * 24
const sessionCookieNameMonth = "session_token_month"
const sessionDurationMonth = time.Hour * 24 * 30

func init() {
	googleConfig = &oauth2.Config{
		ClientID:     Google_ClientID,
		ClientSecret: Google_ClientSecret,
		RedirectURL:  "https://back-0fft.onrender.com/auth/google/callback",
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	if googleConfig.ClientID == "" || googleConfig.ClientSecret == "" {
		log.Fatal("google client id and client secret must be set.")
	}

	log.Println(googleConfig.ClientID)

	facebookConfig = &oauth2.Config{
		ClientID:     Facebook_ClientID,
		ClientSecret: Facebook_ClientSecret,
		RedirectURL:  "https://back-0fft.onrender.com/auth/facebook/callback",
		Scopes:       []string{"public_profile", "email"},
		Endpoint:     facebook.Endpoint,
	}

	if facebookConfig.ClientID == "" || facebookConfig.ClientSecret == "" {
		log.Fatal("facebook client id and client secret must be set.")
	}

	log.Println(facebookConfig.ClientID)
}

var oauthStateString = "random-string-for-csrf-protection jlkjfkejfkljeklfjkekljekjkejfenn'qlepe"

func generateSessionId() (string, error) {
	s_id := make([]byte, 32)
	_, err := rand.Read(s_id)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(s_id), nil
}

func main() {
	initDB()
	r := chi.NewRouter()
	r.Get("/", handle_first)
	r.Post("/login", handle_login)
	r.Post("/logout", handle_logout)
	r.Post("/signup", handle_signup)
	r.Post("/changepass", handle_password_change)
	r.Delete("/delete", handle_delete)

	r.Get("/auth/google", handle_google_login_redirect)
	r.Get("/auth/google/callback", handle_google_callback)

	r.Get("/auth/facebook", handle_facebook_login)
	r.Get("/auth/facebook/callback", handle_facebook_callback)

	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{"https://front-jade-two.vercel.app",
			"https://front-git-main-1f6s-projects.vercel.app",
			"https://front-95njcfsdo-1f6s-projects.vercel.app"},
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "POST", "OPTIONS", "DELETE"},
		AllowedHeaders:   []string{"Content-Type"},
	}).Handler(r)

	go func() {
		log.Println("Server is listening")
		if err := http.ListenAndServe(":3000", corsHandler); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()
	// certFile := "cert.pem"
	// keyFile := "key.pem"
	// go func() {
	// 	log.Println("Server is listening on :3001 (HTTPS)")
	// 	if err := http.ListenAndServeTLS(":3001", certFile, keyFile, corsHandler); err != nil && err != http.ErrServerClosed {
	// 		log.Fatalf("HTTPS server failed: %v", err)
	// 	}
	// }()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	closeDB()
}

func sendCookie(w http.ResponseWriter, first bool, session_id_week string, session_id_months string) {
	if first {
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieNameMonth,
			Value:    session_id_months,
			Expires:  time.Now().Add(sessionDurationMonth),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
			Path:     "/",
		})
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieNameDay,
		Value:    session_id_week,
		Expires:  time.Now().Add(sessionDurationDay),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		Path:     "/",
	})

}

func emptyCookie(w http.ResponseWriter, cookieName string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
}

func handle_first(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	sessionToken, err := r.Cookie(sessionCookieNameDay)
	if err != nil {
		http.Error(w, `{"error":"no short session"}`, http.StatusUnauthorized)
	} else {
		sess := getSession(sessionToken.Value)
		if sess.Authenticated && sess.ExpiresAt.After(time.Now()) {
			log.Println("Getting user for session [authenticated user]:", sess.UserID)

			userinfo, err := getUser(sess.UserID)
			if err != nil {
				http.Error(w, `{"error":"user not found"}`, http.StatusInternalServerError)
				log.Println("GetUser error:", err)
				return
			}
			j, err := json.Marshal(userinfo)
			if err != nil {
				http.Error(w, "Server error", http.StatusInternalServerError)
				log.Fatal(err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(j)
			return
		}
	}

	sessionToken, err = r.Cookie(sessionCookieNameMonth)
	if err != nil {
		http.Error(w, `{"error":"no long session"}`, http.StatusUnauthorized)
		return
	}

	sess := getSession(sessionToken.Value)

	if sess.Authenticated && sess.ExpiresAt.After(time.Now()) {
		log.Println("[INFO] Getting user for session [authenticated user]:", sess.UserID)

		userinfo, err := getUser(sess.UserID)
		if err != nil {
			http.Error(w, `{"error":"user not found"}`, http.StatusInternalServerError)
			return
		}
		session_id := addSession(userinfo.ID, 2)
		sendCookie(w, false, session_id, "")
		j, err := json.Marshal(userinfo)
		if err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
			log.Println("[ERROR] Failed to convert user info into json data. failed: " + err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(j)
		return
	}

	http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
}

func handle_delete(w http.ResponseWriter, r *http.Request) {
	var acc Account
	err := json.NewDecoder(r.Body).Decode(&acc)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		http.Redirect(w, r, "https://front-jade-two.vercel.app/", http.StatusFound)
		log.Println("[WARN] Invalid request body error: " + err.Error())
		return
	}
	deleteUser(acc.Email, acc.Password)
	emptyCookie(w, sessionCookieNameDay)
	emptyCookie(w, sessionCookieNameMonth)
	w.WriteHeader(http.StatusOK)
}

func handle_logout(w http.ResponseWriter, r *http.Request) {
	sessionToken, err := r.Cookie(sessionCookieNameDay)
	if err != nil {
		http.Error(w, `{"error":"no short session"}`, http.StatusUnauthorized)
	} else {
		deleteSession(sessionToken.Value)
	}
	sessionToken, err = r.Cookie(sessionCookieNameMonth)
	if err != nil {
		http.Error(w, `{"error":"no short session"}`, http.StatusUnauthorized)
	} else {
		deleteSession(sessionToken.Value)
	}
	deleteSession(sessionToken.Value)
	emptyCookie(w, sessionCookieNameDay)
	emptyCookie(w, sessionCookieNameMonth)
	w.WriteHeader(http.StatusOK)
}

func handle_signup(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		http.Redirect(w, r, "https://front-jade-two.vercel.app/", http.StatusFound)
		log.Println("[WARN] Invalid request body error: " + err.Error())
		return
	}
	if user.Email != "" && validateUserByEmail(user.Email) {
		http.Error(w, "This email is registred.", http.StatusBadRequest)
		http.Redirect(w, r, "https://front-jade-two.vercel.app/", http.StatusFound)
		log.Println("[WARN] Registered email.")
		return
	}

	if user.PhoneNumber != "" && validateUserByPhone(user.PhoneNumber) {
		http.Error(w, "This phone number is registred.", http.StatusBadRequest)
		http.Redirect(w, r, "https://front-jade-two.vercel.app/", http.StatusFound)
		log.Println("[WARN] Registered phone number.")
		return
	}

	id, session_short, session_long := addUser(&user)
	user.ID = id
	sendCookie(w, true, session_short, session_long)
	j, err := json.Marshal(user)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		log.Println("[ERROR] Failed to convert user info into json data. failed: " + err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)

}

func handle_login(w http.ResponseWriter, r *http.Request) {
	var acc Account
	err := json.NewDecoder(r.Body).Decode(&acc)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Println("[ERROR] Invalid request body error: " + err.Error())
		return
	}
	user, err := validateUser(acc.Email, acc.Password)
	if err != nil {
		http.Error(w, "Invalid credentials error", http.StatusUnauthorized)
		log.Println("[ERROR] Invalid credentials error: " + err.Error())
		return
	}
	j, err := json.Marshal(user)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		log.Println("[ERROR] Failed to convert user info into json data. failed: " + err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

func handle_password_change(w http.ResponseWriter, r *http.Request) {
	var acc Account
	err := json.NewDecoder(r.Body).Decode(&acc)
	if err != nil {
		log.Println("[ERROR] Invalid request body error: " + err.Error())
		return
	}
	change_password(acc.Email, acc.Password, acc.NewPassword)
}

func handle_google_login_redirect(w http.ResponseWriter, r *http.Request) {
	url := googleConfig.AuthCodeURL(oauthStateString, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handle_google_callback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state != oauthStateString {
		http.Error(w, "State mismatch: CSRF attack detected!", http.StatusUnauthorized)
		log.Printf("[FATAL] Google callback state mismatch. Expected: %s, Got: %s", oauthStateString, state)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "Authorization code not provided", http.StatusBadRequest)
		log.Println("[ERROR] Google callback: No authorization code.")
		return
	}

	token, err := googleConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange code for token: "+err.Error(), http.StatusInternalServerError)
		log.Printf("[ERROR] Google token exchange error: %v", err)
		return
	}

	client := googleConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "Failed to get user info from Google: "+err.Error(), http.StatusInternalServerError)
		log.Printf("[ERROR] Google call error: %v", err)
		return
	}

	defer resp.Body.Close()
	var userinfo GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userinfo); err != nil {
		log.Println("[ERROR] Invalid response body error: " + err.Error())
	}

	user := User{Username: userinfo.Name, Firstname: userinfo.Given_name, Lastname: userinfo.Family_name, Email: userinfo.Email, Password: "external_login", GoogleID: userinfo.ID, ImageURL: userinfo.PictureURL}
	var session_id_day string
	var session_id_month string

	var id int

	if !validateUserByEmail(user.Email) {
		_, session_id_day, session_id_month = addUser(&user)
		sendCookie(w, true, session_id_day, session_id_month)
	} else {
		id = getUserId(user.Email)
		session_id_day = getSessionForUserID(user.ID, 1)
		session_id_month = getSessionForUserID(user.ID, 2)
		if session_id_day == "" && session_id_month == "" {
			session_id_day = addSession(id, 1)
			session_id_month = addSession(id, 2)
			sendCookie(w, true, session_id_day, session_id_month)
		} else if session_id_day == "" && session_id_month != "" {
			session_id_day = addSession(id, 1)
			sendCookie(w, false, session_id_day, "")
		}
	}
	http.Redirect(w, r, "https://front-jade-two.vercel.app", http.StatusFound)
}

func splitFullName(fullName string) (firstName, lastName string) {
	names := strings.Fields(fullName)
	if len(names) == 0 {
		return "", ""
	} else if len(names) == 1 {
		return names[0], ""
	} else {
		firstName = names[0]
		lastName = strings.Join(names[1:], " ")
		return firstName, lastName
	}
}

func handle_facebook_login(w http.ResponseWriter, r *http.Request) {
	url := facebookConfig.AuthCodeURL(oauthStateString, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handle_facebook_callback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state != oauthStateString {
		http.Error(w, "State mismatch: CSRF attack detected!", http.StatusUnauthorized)
		log.Printf("[ERROR]Facebook callback state mismatch. Expected: %s, Got: %s", oauthStateString, state)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "Authorization code not provided", http.StatusBadRequest)
		log.Println("[ERROR] Facebook callback: No authorization code.")
		return
	}

	token, err := facebookConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange code for token: "+err.Error(), http.StatusInternalServerError)
		log.Printf("[ERROR] Facebook token exchange error: %v", err)
		return
	}

	graphAPIURL := fmt.Sprintf("https://graph.facebook.com/me?fields=id,name,email&access_token=%s", url.QueryEscape(token.AccessToken))
	resp, err := http.Get(graphAPIURL)
	if err != nil {
		http.Error(w, "Failed to get user info from Facebook: "+err.Error(), http.StatusInternalServerError)
		log.Printf("[ERROR] Facebook Graph API call error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to get user info from Facebook (API error)", http.StatusInternalServerError)
		log.Printf("[ERROR] Failed to get user info error: %v", resp.StatusCode)
		return
	}

	var userinfo FacebookUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userinfo); err != nil {
		http.Error(w, "Failed to parse Facebook user info: "+err.Error(), http.StatusInternalServerError)
		log.Printf("Facebook user info JSON decode error: %v", err)
		return
	}

	user := User{Username: userinfo.Name, Email: userinfo.Email, Password: "external_login", GoogleID: userinfo.ID, ImageURL: userinfo.Picture.Data.URL}
	user.Firstname, user.Lastname = splitFullName(user.Username)
	var session_id_day string
	var session_id_month string
	var id int
	if !validateUserByEmail(user.Email) {
		_, session_id_day, session_id_month = addUser(&user)
		sendCookie(w, true, session_id_day, session_id_month)
	} else {
		id = getUserId(user.Email)
		session_id_day = getSessionForUserID(user.ID, 1)
		session_id_month = getSessionForUserID(user.ID, 2)
		if session_id_day == "" && session_id_month == "" {
			session_id_day = addSession(id, 1)
			session_id_month = addSession(id, 2)
			sendCookie(w, true, session_id_day, session_id_month)
		} else if session_id_day == "" && session_id_month != "" {
			session_id_day = addSession(id, 1)
			sendCookie(w, false, session_id_day, "")
		}
	}

	http.Redirect(w, r, "https://front-jade-two.vercel.app/", http.StatusFound)
}
