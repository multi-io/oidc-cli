package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"html/template"
	"net/http"
)

type Scopes []string

func (s *Scopes) String() string {
	return fmt.Sprintf("%s", *s)
}

func (s *Scopes) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type Server struct {
	Port         int
	IssuerURL    string
	ClientID     string
	ClientSecret string
	Scopes       Scopes
	SelfURL      string

	httpServer       *http.Server
	cookieStore      sessions.Store
	serverFinishChan chan error
	serverFinishErr  error
	provider         *oidc.Provider
	config           *oauth2.Config
	tokenVerifier    *oidc.IDTokenVerifier

	indexTemplate *template.Template
}

const SESS_IDTOKENCLAIMS = "idtokenclaims"
const SESS_STATE = "state"

type TemplateData struct {
	Request     *http.Request
	Writer      http.ResponseWriter
	Server      *Server
	IdTokenJson interface{}
	AuthCodeURL string
	Errors      []string
}

func (data *TemplateData) error(msg string) {
	data.Errors = append(data.Errors, msg)
}

func NewServer(ctx context.Context,
	port int,
	issuerURL string,
	clientID string,
	clientSecret string,
	scopes Scopes,
	selfURL string,
) (*Server, error) {
	server := &Server{
		Port:         port,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		IssuerURL:    issuerURL,
		Scopes:       scopes,
		SelfURL:      selfURL,
	}

	var err error
	server.provider, err = oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("Couldn't initialize OIDC client: %v", err)
	}

	server.config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		RedirectURL:  fmt.Sprintf("%s/", selfURL),
		Endpoint:     server.provider.Endpoint(),
	}

	server.tokenVerifier = server.provider.Verifier(&oidc.Config{ClientID: clientID})

	mux := &http.ServeMux{}
	server.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	//gob.Register(oidc.IDToken{})
	gob.Register(make(map[string]interface{}))

	// TODO for prod: key from environment, not hardcoded; list of keys for rotation
	server.cookieStore = sessions.NewCookieStore([]byte("super-secret-key"))
	//server.cookieStore = sessions.NewFilesystemStore("/tmp/cookies", []byte("super-secret-key"))

	server.indexTemplate = template.Must(template.ParseFiles("server/templates/index.html"))

	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		server.handleIndex(writer, request)
	})

	server.serverFinishChan = make(chan error, 1)

	return server, nil
}

func (server *Server) Start() {
	go func() {
		server.serverFinishErr = server.httpServer.ListenAndServe()
		server.serverFinishChan <- server.serverFinishErr
	}()
}

func (server *Server) Stop(ctx context.Context) error {
	return server.httpServer.Shutdown(ctx)
}

func (server *Server) Close() error {
	return server.httpServer.Close()
}

func (server *Server) Join() error {
	return <-server.serverFinishChan
}

//

func randString() string {
	buf := make([]byte, 32)
	rand.Read(buf)
	return base64.StdEncoding.EncodeToString(buf)
}

func (server *Server) handleIndex(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.Error(writer, fmt.Sprintf("Path not found: %s", request.URL.Path), http.StatusNotFound)
		return
	}

	session, err := server.cookieStore.Get(request, "mysession")
	if err != nil {
		http.Error(writer, fmt.Sprintf("Session decode error: %s", err), http.StatusInternalServerError)
		return
	}

	data := TemplateData{
		Request: request,
		Writer:  writer,
		Server:  server,
	}

	reqState := request.URL.Query().Get("state")
	reqCode := request.URL.Query().Get("code")

	ctx := request.Context()

	if reqState != "" && reqCode != "" {
		// looks like we were called back by the auth server. Perform token exchange

		if reqState != session.Values[SESS_STATE] {
			data.error("callback error: invalid state")
		} else {

			oauthToken, err := server.config.Exchange(ctx, reqCode)
			if err != nil {
				data.error(fmt.Sprintf("Exchange error: %s", err))
			} else if rawIdToken, ok := oauthToken.Extra("id_token").(string); ok {
				idToken, err := server.tokenVerifier.Verify(ctx, rawIdToken)
				if err != nil {
					data.error(fmt.Sprintf("ID token verification error: %s", err))
				} else {
					var claims interface{}
					if err := idToken.Claims(&claims); err != nil {
						data.error(fmt.Sprintf("ID token decode error: %s", err))
					} else {
						session.Values[SESS_IDTOKENCLAIMS] = claims
						if err := session.Save(request, writer); err != nil {
							data.error(fmt.Sprintf("session save error: %s", err))
						}
						// TODO maybe redirect to self here to get rid of the request parameters in the URL bar
					}
				}
			}
		}
	}

	if idTokenClaims, ok := session.Values[SESS_IDTOKENCLAIMS].(interface{}); ok {
		// logged in
		data.IdTokenJson = idTokenClaims

	} else {
		// not logged in
		state := randString()
		session.Values[SESS_STATE] = state
		if err := session.Save(request, writer); err != nil {
			data.error(fmt.Sprintf("session save error: %s", err))
		}
		data.AuthCodeURL = server.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	}

	if err := server.indexTemplate.Execute(writer, data); err != nil {
		http.Error(writer, fmt.Sprintf("Template rendering error: %s", err), http.StatusInternalServerError)
	}
}
