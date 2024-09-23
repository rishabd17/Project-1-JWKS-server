package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey

// Key represents the JWK structure
type Key struct {
	Kid       string `json:"kid"`
	PublicKey string `json:"publicKey"`
	Expiry    int64  `json:"expiry"`
}

// JWKSResponse represents the response structure for JWKS
type JWKSResponse struct {
	Keys []Key `json:"keys"`
}

// initKeys initializes RSA key pairs
func initKeys() {
	var err error
	// Generate a new RSA private key
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048) // 2048 bits is a common size
	if err != nil {
		log.Fatalf("Error generating keys: %v", err)
	}
	publicKey = &privateKey.PublicKey

	// Save the private key to a file
	privateKeyFile, err := os.Create("private_key.pem")
	if err != nil {
		log.Fatalf("Error creating private key file: %v", err)
	}
	defer privateKeyFile.Close()

	err = pem.Encode(privateKeyFile, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		log.Fatalf("Error writing private key to file: %v", err)
	}

	// Save the public key to a file
	publicKeyFile, err := os.Create("public_key.pem")
	if err != nil {
		log.Fatalf("Error creating public key file: %v", err)
	}
	defer publicKeyFile.Close()

	publicKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	err = pem.Encode(publicKeyFile, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	if err != nil {
		log.Fatalf("Error writing public key to file: %v", err)
	}
}

// JWKSHandler serves the public keys in JWKS format
func JWKSHandler(w http.ResponseWriter, r *http.Request) {
	now := time.Now().Unix()
	key := Key{
		Kid:       "1",
		PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(publicKey)})),
		Expiry:    now + 3600, // 1 hour expiry
	}

	response := JWKSResponse{Keys: []Key{key}}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// AuthHandler issues a signed JWT
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	claims := jwt.MapClaims{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"kid": "1",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		http.Error(w, "Could not create token", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(tokenString))
}

// main function sets up the server and routes
func main() {
	initKeys()

	r := mux.NewRouter()
	r.HandleFunc("/.well-known/jwks.json", JWKSHandler).Methods("GET")
	r.HandleFunc("/auth", AuthHandler).Methods("POST")

	log.Println("Server starting on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", r))
}
