package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Scopes []string

func (s *Scopes) String() string {
	return fmt.Sprintf("%s", *s)
}

func (s *Scopes) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func randString() string {
	buf := make([]byte, 32)
	rand.Read(buf)
	return base64.StdEncoding.EncodeToString(buf)
}

func main() {
	var (
		port         = flag.Int("port", 8080, "Callback port")
		path         = flag.String("path", "/oauth/callback", "Callback path")
		clientID     = flag.String("id", "", "Client ID")
		clientSecret = flag.String("secret", "", "Client secret")
		issuerURL    = flag.String("issuer", "", "OIDC Issuer URL")
		//authURL      = flag.String("auth", "", "Authorization URL")
		//tokenURL     = flag.String("token", "", "Token URL")
		scopes       Scopes
	)
	flag.Var(&scopes, "scope", "oAuth scopes to authorize (can be specified multiple times")
	flag.Parse()

	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, *issuerURL);
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't initialize OIDC client: %v", err);
		os.Exit(1);
	}

	config := &oauth2.Config{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		Scopes:       scopes,
		RedirectURL:  fmt.Sprintf("http://127.0.0.1:%d%s", *port, *path),
		Endpoint: provider.Endpoint(),
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: *clientID})

	state := randString()
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	fmt.Printf("Visit this URL in your browser:\n\n%s\n\n", url)

	var wg sync.WaitGroup
	wg.Add(1)

	http.HandleFunc(*path, func(w http.ResponseWriter, r *http.Request) {
		defer wg.Done()

		if s := r.URL.Query().Get("state"); s != state {
			http.Error(w, fmt.Sprintf("Invalid state: %s", s), http.StatusUnauthorized)
			return
		}

		code := r.URL.Query().Get("code")
		oauthToken, err := config.Exchange(ctx, code)
		if err != nil {
			http.Error(w, fmt.Sprintf("Exchange error: %s", err), http.StatusServiceUnavailable)
			return
		}

		oauthTokenJSON, err := json.MarshalIndent(oauthToken, "", "  ")
		if err != nil {
			http.Error(w, fmt.Sprintf("Token parse error: %s", err), http.StatusServiceUnavailable)
			return
		}

		w.Write(oauthTokenJSON)

		if rawIdToken, ok := oauthToken.Extra("id_token").(string); ok {
			idToken, err := verifier.Verify(ctx, rawIdToken);
			if err != nil {
				http.Error(w, fmt.Sprintf("ID token verification error: %s", err), http.StatusServiceUnavailable)
			} else {
				var idTokenJson interface{};
				if err := idToken.Claims(&idTokenJson); err != nil {
					http.Error(w, fmt.Sprintf("ID token decode error: %s", err), http.StatusServiceUnavailable)
				} else {
					idTokenJsonIndented, err := json.MarshalIndent(idTokenJson, "", "  ")
					if err != nil {
						http.Error(w, fmt.Sprintf("ID token JSON output error: %s", err), http.StatusServiceUnavailable)
						return
					}
					w.Write(idTokenJsonIndented);
				}
			}
		}
	})

	server := http.Server{
		Addr: fmt.Sprintf(":%d", *port),
	}

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalln(err)
		}
	}()

	wg.Wait()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalln(err)
	}
}
