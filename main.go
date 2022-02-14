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
		port = flag.Int("port", 8080, "Callback port")
		//path         = flag.String("path", "/oauth/callback", "Callback path")
		selfURL      = flag.String("self", "http://127.0.0.1:8080", "Public base URL of this client")
		clientID     = flag.String("id", "", "Client ID")
		clientSecret = flag.String("secret", "", "Client secret")
		issuerURL    = flag.String("issuer", "", "OIDC Issuer URL")
		//authURL      = flag.String("auth", "", "Authorization URL")
		//tokenURL     = flag.String("token", "", "Token URL")
		scopes server.Scopes
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
}
