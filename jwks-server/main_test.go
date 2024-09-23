package main

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestMain(m *testing.M) {
    initKeys() // Ensure keys are initialized before running tests
    m.Run()
}

func TestJWKSHandler(t *testing.T) {
    req, err := http.NewRequest("GET", "/.well-known/jwks.json", nil)
    if err != nil {
        t.Fatalf("Failed to create request: %v", err)
    }

    recorder := httptest.NewRecorder()
    handler := http.HandlerFunc(JWKSHandler)

    handler.ServeHTTP(recorder, req)

    if status := recorder.Code; status != http.StatusOK {
        t.Errorf("Expected status 200 OK, got %v", status)
    }
}
