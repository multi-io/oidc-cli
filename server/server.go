package server

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
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

	httpServer       *http.Server
	serverFinishChan chan error
	serverFinishErr  error
	provider         *oidc.Provider
	config           *oauth2.Config
	tokenVerifier    *oidc.IDTokenVerifier
}

type TemplateData struct {
	Request *http.Request
	Writer  http.ResponseWriter
	Server  *Server
}

func NewServer(ctx context.Context,
	port int,
	issuerURL string,
	clientID string,
	clientSecret string,
	scopes Scopes,
) (*Server, error) {
	server := &Server{
		Port:         port,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		IssuerURL:    issuerURL,
		Scopes:       scopes,
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
		RedirectURL:  fmt.Sprintf("http://127.0.0.1:%d%s/", port),
		Endpoint:     server.provider.Endpoint(),
	}

	server.tokenVerifier = server.provider.Verifier(&oidc.Config{ClientID: clientID})

	mux := &http.ServeMux{}
	server.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	template := template.Must(template.ParseFiles("server/templates/index.html"))
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		data := TemplateData{
			Request: request,
			Writer:  writer,
			Server:  server,
		}
		template.Execute(writer, data)
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
