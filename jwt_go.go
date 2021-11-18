//https://learn.vonage.com/blog/2020/03/13/using-jwt-for-authentication-in-a-golang-application-dr/

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"
)

type Token struct {
	Token   string `json:"token"`
	RFToken string `json:"refreshToken"`
}

func verify(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenValue := req.Header.Get("Authorization")
	tokenData, err := verifyToken(tokenValue)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	claims, ok := tokenData.Claims.(jwt.MapClaims)
	if !tokenData.Valid && !ok {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	userId := fmt.Sprintf("%s", claims["user_id"])
	resp := make(map[string]string)
	resp["userId"] = userId
	resp["userName"] = fmt.Sprintf("%s", claims["user_name"])

	js, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(200)
	w.Write(js)
}

func verifyToken(token string) (*jwt.Token, error) {
	tokenParse, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("SECRET_TOKEN_JWT")), nil
	})
	if err != nil {
		return nil, err
	}
	return tokenParse, nil
}

func index(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userId := uuid.NewV4().String()
	tokendata, _ := createToken(userId)

	resp := make(map[string]string)
	resp["message"] = tokendata.Token

	js, err := json.Marshal(tokendata)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(200)
	w.Write(js)
}

func refresh(w http.ResponseWriter, req *http.Request) {
	userId := uuid.NewV4().String()
	createToken(userId)
}

func createToken(userId string) (Token, error) {
	claims := jwt.MapClaims{}
	claims["authorized"] = true
	claims["user_id"] = userId
	claims["user_name"] = "Testing Username"
	claims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := at.SignedString([]byte(os.Getenv("SECRET_TOKEN_JWT")))
	if err != nil {
		return Token{}, err
	}

	rfClaims := jwt.MapClaims{}
	rfClaims["user_id"] = userId
	rfClaims["user_name"] = "Testing Username"
	rfClaims["exp"] = time.Now().Add(time.Hour * 24 * 7).Unix()
	rfAt := jwt.NewWithClaims(jwt.SigningMethodHS256, rfClaims)
	rfToken, err := rfAt.SignedString([]byte(os.Getenv("SECRET_TOKEN_JWT")))
	if err != nil {
		return Token{}, err
	}

	return Token{
		Token:   token,
		RFToken: rfToken,
	}, nil
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/verify", verify)
	r.HandleFunc("/", index)

	http.Handle("/", r)
	http.ListenAndServe(":8090", nil)
}
