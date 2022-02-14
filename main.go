package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/multi-io/oidc-cli/server"
	"net/http"
	"os"
)


func main() {
	var (
		port         = flag.Int("port", 8080, "Callback port")
		//path         = flag.String("path", "/oauth/callback", "Callback path")
		selfURL      = flag.String("self", "http://127.0.0.1:8080", "Public base URL of this client")
		clientID     = flag.String("id", "", "Client ID")
		clientSecret = flag.String("secret", "", "Client secret")
		issuerURL    = flag.String("issuer", "", "OIDC Issuer URL")
		//authURL      = flag.String("auth", "", "Authorization URL")
		//tokenURL     = flag.String("token", "", "Token URL")
		scopes       server.Scopes
	)
	flag.Var(&scopes, "scope", "oAuth scopes to authorize (can be specified multiple times")
	flag.String("path", "/oauth/callback", "Callback path") // just parse & forget it to be compatible for now
	flag.Parse()

	ctx := context.Background()

	server, err := server.NewServer(ctx, *port, *issuerURL, *clientID, *clientSecret, scopes, *selfURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't create webserver: %v", err)
		os.Exit(1)
	}

	server.Start()
	if err := server.Join(); err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "Webserver error: %v", err)
		os.Exit(1)
	}

	os.Exit(0)

	//provider, err := oidc.NewProvider(ctx, *issuerURL);
	//if err != nil {
	//	fmt.Fprintf(os.Stderr, "Couldn't initialize OIDC client: %v", err);
	//	os.Exit(1);
	//}
	//
	//config := &oauth2.Config{
	//	ClientID:     *clientID,
	//	ClientSecret: *clientSecret,
	//	Scopes:       scopes,
	//	RedirectURL:  fmt.Sprintf("http://127.0.0.1:%d%s", *port, *path),
	//	Endpoint: provider.Endpoint(),
	//}
	//
	//verifier := provider.Verifier(&oidc.Config{ClientID: *clientID})
	//
	//state := randString()
	//url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	//fmt.Printf("Visit this URL in your browser:\n\n%s\n\n", url)
	//
	//var wg sync.WaitGroup
	//wg.Add(1)
	//
	//http.HandleFunc(*path, func(w http.ResponseWriter, r *http.Request) {
	//	defer wg.Done()
	//
	//	if s := r.URL.Query().Get("state"); s != state {
	//		http.Error(w, fmt.Sprintf("Invalid state: %s", s), http.StatusUnauthorized)
	//		return
	//	}
	//
	//	code := r.URL.Query().Get("code")
	//	oauthToken, err := config.Exchange(ctx, code)
	//	if err != nil {
	//		http.Error(w, fmt.Sprintf("Exchange error: %s", err), http.StatusServiceUnavailable)
	//		return
	//	}
	//
	//	oauthTokenJSON, err := json.MarshalIndent(oauthToken, "", "  ")
	//	if err != nil {
	//		http.Error(w, fmt.Sprintf("Token parse error: %s", err), http.StatusServiceUnavailable)
	//		return
	//	}
	//
	//	w.Write(oauthTokenJSON)
	//
	//	if rawIdToken, ok := oauthToken.Extra("id_token").(string); ok {
	//		idToken, err := verifier.Verify(ctx, rawIdToken);
	//		if err != nil {
	//			http.Error(w, fmt.Sprintf("ID token verification error: %s", err), http.StatusServiceUnavailable)
	//		} else {
	//			var idTokenJson interface{};
	//			if err := idToken.Claims(&idTokenJson); err != nil {
	//				http.Error(w, fmt.Sprintf("ID token decode error: %s", err), http.StatusServiceUnavailable)
	//			} else {
	//				idTokenJsonIndented, err := json.MarshalIndent(idTokenJson, "", "  ")
	//				if err != nil {
	//					http.Error(w, fmt.Sprintf("ID token JSON output error: %s", err), http.StatusServiceUnavailable)
	//					return
	//				}
	//				w.Write(idTokenJsonIndented);
	//			}
	//		}
	//	}
	//})
	//
	//server := http.Server{
	//	Addr: fmt.Sprintf(":%d", *port),
	//}
	//
	//go func() {
	//	if err := server.ListenAndServe(); err != http.ErrServerClosed {
	//		log.Fatalln(err)
	//	}
	//}()
	//
	//wg.Wait()
	//if err := server.Shutdown(ctx); err != nil {
	//	log.Fatalln(err)
	//}
}
