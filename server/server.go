package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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
	cookieStore      *sessions.CookieStore
	serverFinishChan chan error
	serverFinishErr  error
	provider         *oidc.Provider
	config           *oauth2.Config
	tokenVerifier    *oidc.IDTokenVerifier

	indexTemplate *template.Template
}

const SESSIONCOOKIE = "sessid"
const SESS_IDTOKEN = "idtoken"

type TemplateData struct {
	Request     *http.Request
	Writer      http.ResponseWriter
	Server      *Server
	IdToken     *oidc.IDToken
	AuthCodeURL string
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

	server.cookieStore = sessions.NewCookieStore([]byte("super-secret-key"))

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
	session, err := server.cookieStore.Get(request, SESSIONCOOKIE)
	if err != nil {
		http.Error(writer, fmt.Sprintf("Session decode error: %s", err), http.StatusInternalServerError)
		return
	}

	data := TemplateData{
		Request: request,
		Writer:  writer,
		Server:  server,
	}

	if idToken, ok := session.Values[SESS_IDTOKEN].(*oidc.IDToken); ok && idToken != nil {
		// logged in
		data.IdToken = idToken
	} else {
		// not logged in
		state := randString()
		data.AuthCodeURL = server.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	}

	if err := server.indexTemplate.Execute(writer, data); err != nil {
		http.Error(writer, fmt.Sprintf("Template rendering error: %s", err), http.StatusInternalServerError)
	}
}
