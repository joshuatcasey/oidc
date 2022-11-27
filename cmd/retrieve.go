package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/MicahParks/keyfunc"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/joshuatcasey/oidc/printers"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var retrieveCmd = &cobra.Command{
	Use:   "retrieve",
	Short: "Retrieve ID token",
	Long:  `Launch a browser to retrieve the id token`,
	Run:   retrieve,
}

var (
	issuerUri    string
	clientId     string
	clientSecret string
	port         int
	redirectUri  string
	state        = uuid.New().String()
	outputFormat string
	usePkce      bool
	codeVerifier string
)

func init() {
	rootCmd.AddCommand(retrieveCmd)

	retrieveCmd.Flags().StringVar(&issuerUri, "issuerUri", "", "Issuer URI")
	err := retrieveCmd.MarkFlagRequired("issuerUri")
	if err != nil {
		panic(err)
	}

	retrieveCmd.Flags().StringVar(&clientId, "clientId", "", "Client ID")
	err = retrieveCmd.MarkFlagRequired("clientId")
	if err != nil {
		panic(err)
	}

	retrieveCmd.Flags().StringVar(&clientSecret, "clientSecret", "", "Client Secret")
	err = retrieveCmd.MarkFlagRequired("clientSecret")
	if err != nil {
		panic(err)
	}

	retrieveCmd.Flags().StringVar(&outputFormat, "outputFormat", "claims", "Output format. Defaults to 'claims'. Choose from: ['claims', 'raw', 'json', 'jwt.io']")
	retrieveCmd.Flags().IntVar(&port, "port", 8080, "Port for the CLI to receive a code")
	retrieveCmd.Flags().StringVar(&redirectUri, "redirectUri", "http://localhost:8080", "Redirect URI for the client")
	retrieveCmd.Flags().BoolVar(&usePkce, "pkce", false, "Use PKCE")
}

func calcSha256(s string) string {
	b := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func retrieve(_ *cobra.Command, _ []string) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuerUri)
	if err != nil {
		panic(err)
	}

	authorizationUrl, err := url.Parse(provider.Endpoint().AuthURL)
	if err != nil {
		panic(err)
	}

	authorizationParams := url.Values{}
	authorizationParams.Set("response_type", "code")
	authorizationParams.Set("client_id", clientId)
	authorizationParams.Set("redirect_uri", redirectUri)
	authorizationParams.Set("scope", oidc.ScopeOpenID)
	authorizationParams.Set("state", state)

	if usePkce {
		codeVerifier = uuid.New().String() + "-" + uuid.New().String()
		codeChallenge := calcSha256(codeVerifier)
		codeChallengeMethod := "S256"

		authorizationParams.Set("code_challenge", codeChallenge)
		authorizationParams.Set("code_challenge_method", codeChallengeMethod)
	}

	authorizationUrl.RawQuery = authorizationParams.Encode()

	var wg = new(sync.WaitGroup)
	codeChan := make(chan string)
	jwtChan := make(chan string)

	server := http.Server{}
	server.Addr = fmt.Sprintf(":%d", port)
	server.Handler = receiveCodeFunc(codeChan, wg)

	wg.Add(1)
	go func() {
		err = server.ListenAndServe()
		if err != nil {
			panic(err)
		}
	}()

	wg.Add(1)
	go exchangeForToken(codeChan, jwtChan, wg, provider, ctx)

	wg.Add(1)
	go translateTokenToClaims(jwtChan, wg, provider)

	err = browser.OpenURL(authorizationUrl.String())
	if err != nil {
		panic(err)
	}

	wg.Wait()
}

func translateTokenToClaims(jwtChan chan string, wg *sync.WaitGroup, provider *oidc.Provider) {
	defer wg.Done()
	stringToken := <-jwtChan

	var oidcConfigClaims struct {
		JwksUri string `json:"jwks_uri"`
	}

	if err := provider.Claims(&oidcConfigClaims); err != nil || oidcConfigClaims.JwksUri == "" {
		panic(fmt.Errorf("cannot find jwks_uri: %w", err))
	}

	// Create the JWKS from the resource at the given URL.
	jwks, err := keyfunc.Get(oidcConfigClaims.JwksUri, keyfunc.Options{}) // See recommended options in the examples directory.
	if err != nil {
		log.Fatalf("Failed to get the JWKS from the given URL.\nError: %s", err)
	}

	token, err := jwt.Parse(stringToken, jwks.Keyfunc)
	if err != nil {
		panic(err)
	}

	if !token.Valid {
		panic("token not valid")
	}

	tokenPrinters := make(map[string]printers.Printer)
	tokenPrinters["claims"] = printers.PrintAsClaims
	tokenPrinters["json"] = printers.PrintClaimsAsJson
	tokenPrinters["raw"] = printers.PrintRaw
	tokenPrinters["jwt.io"] = printers.PrintJwtIo

	if tokenPrinter, ok := tokenPrinters[outputFormat]; ok {
		if err = tokenPrinter(token, stringToken); err != nil {
			panic(fmt.Errorf("cannot print as %s: %w", outputFormat, err))
		}
	} else {
		fmt.Printf("unknown outputFormat=%s\n", outputFormat)
	}
}

func exchangeForToken(codeChan chan string, jwtChan chan string, wg *sync.WaitGroup, provider *oidc.Provider, ctx context.Context) {
	defer wg.Done()

	code := <-codeChan

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURL:  redirectUri,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	var opts []oauth2.AuthCodeOption

	if usePkce && codeVerifier != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	}

	oauth2Token, err := oauth2Config.Exchange(ctx, code, opts...)
	if err != nil {
		panic(err)
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		panic("no id token")
	}

	jwtChan <- rawIDToken
}

func receiveCodeFunc(codeChan chan string, wg *sync.WaitGroup) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "NotFound", http.StatusNotFound)
			return
		}

		query, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil {
			return
		}

		if query.Has("code") {
			if !query.Has("state") {
				panic("code must be accompanied by state")
			} else if state != query.Get("state") {
				panic("state does not match")
			}

			code := query.Get("code")
			codeChan <- code
			wg.Done()
		}
	}
}
