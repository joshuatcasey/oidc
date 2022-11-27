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
	nonce        = uuid.New().String()
)

func init() {
	rootCmd.AddCommand(retrieveCmd)

	retrieveCmd.Flags().StringVar(&issuerUri, "issuerUri", "", "Issuer URI")
	err := retrieveCmd.MarkFlagRequired("issuerUri")
	if err != nil {
		log.Fatal(fmt.Errorf("could not mark issuerUri as required: %w\n", err))
	}

	retrieveCmd.Flags().StringVar(&clientId, "clientId", "", "Client ID")
	err = retrieveCmd.MarkFlagRequired("clientId")
	if err != nil {
		log.Fatal(fmt.Errorf("could not mark clientId as required: %w\n", err))
	}

	retrieveCmd.Flags().StringVar(&clientSecret, "clientSecret", "", "Client Secret")
	err = retrieveCmd.MarkFlagRequired("clientSecret")
	if err != nil {
		log.Fatal(fmt.Errorf("could not mark clientSecret as required: %w\n", err))
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
		log.Fatal(fmt.Errorf("unable to create OIDC provider: %w", err))
	}

	authorizationUrl, err := url.Parse(provider.Endpoint().AuthURL)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to parse authorizationUrl [%s]: %w", provider.Endpoint().AuthURL, err))
	}

	authorizationParams := url.Values{}
	authorizationParams.Set("response_type", "code")
	authorizationParams.Set("client_id", clientId)
	authorizationParams.Set("redirect_uri", redirectUri)
	authorizationParams.Set("scope", oidc.ScopeOpenID)
	authorizationParams.Set("state", state)
	authorizationParams.Set("nonce", nonce)

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
			close(codeChan)
			close(jwtChan)
			log.Fatal(fmt.Errorf("unable to parse authorizationUrl [%s]: %w", provider.Endpoint().AuthURL, err))
		}
	}()

	wg.Add(1)
	go exchangeForToken(codeChan, jwtChan, wg, provider, ctx)

	wg.Add(1)
	go translateTokenToClaims(jwtChan, wg, provider)

	authorizationUrlStr := authorizationUrl.String()
	err = browser.OpenURL(authorizationUrlStr)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to open url [%s]: %w", authorizationUrlStr, err))
	}

	wg.Wait()
}

func translateTokenToClaims(jwtChan chan string, wg *sync.WaitGroup, provider *oidc.Provider) {
	defer wg.Done()

	stringToken, ok := <-jwtChan
	if !ok {
		return
	}

	var oidcConfigClaims struct {
		JwksUri string `json:"jwks_uri"`
	}

	if err := provider.Claims(&oidcConfigClaims); err != nil || oidcConfigClaims.JwksUri == "" {
		fmt.Print(fmt.Errorf("cannot find jwks_uri: %w", err))
		return
	}

	// Create the JWKS from the resource at the given URL.
	jwks, err := keyfunc.Get(oidcConfigClaims.JwksUri, keyfunc.Options{}) // See recommended options in the examples directory.
	if err != nil {
		log.Fatalf("Failed to get the JWKS from the given URL.\nError: %s", err)
	}

	token, err := jwt.Parse(stringToken, jwks.Keyfunc)
	if err != nil {
		fmt.Print(fmt.Errorf("unable to parse JWT"))
		return
	}

	if !token.Valid {
		fmt.Printf("token not valid\n")
		return
	}

	if !validateNonce(token) {
		return
	}

	tokenPrinters := make(map[string]printers.Printer)
	tokenPrinters["claims"] = printers.PrintAsClaims
	tokenPrinters["json"] = printers.PrintClaimsAsJson
	tokenPrinters["raw"] = printers.PrintRaw
	tokenPrinters["jwt.io"] = printers.PrintJwtIo

	if tokenPrinter, ok := tokenPrinters[outputFormat]; !ok {
		fmt.Printf("unknown outputFormat=%s\n", outputFormat)
		return
	} else if err = tokenPrinter(token, stringToken); err != nil {
		fmt.Print(fmt.Errorf("cannot print as %s: %w", outputFormat, err))
		return
	}
}

func validateNonce(token *jwt.Token) bool {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Printf("cannot access claims from token\n")
		return false
	}

	if nonceClaim, ok := claims["nonce"]; !ok {
		fmt.Printf("cannot find nonce in the id_token\n")
		return false
	} else if nonceClaim != nonce {
		fmt.Printf("nonce does not match\n")
		return false
	}

	return true
}

func exchangeForToken(codeChan chan string, jwtChan chan string, wg *sync.WaitGroup, provider *oidc.Provider, ctx context.Context) {
	defer wg.Done()

	code, ok := <-codeChan
	if !ok {
		close(jwtChan)
		return
	}

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
		close(jwtChan)
		fmt.Print(fmt.Errorf("unable to exchange code for token: %w", err))
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		close(jwtChan)
		fmt.Print(fmt.Errorf("no id_token in the access token response: %w", err))
		return
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

		if query.Has("error") || query.Has("error_description") || query.Has("error_uri") {
			fmt.Printf("error=%s\n", query.Get("error"))
			fmt.Printf("error_description=%s\n", query.Get("error_description"))
			fmt.Printf("error_uri=%s\n", query.Get("error_uri"))

			close(codeChan)
			wg.Done()
		}

		if query.Has("code") {
			if !query.Has("state") {
				fmt.Printf("code must be accompanied by state\n")
				close(codeChan)
				wg.Done()
			} else if state != query.Get("state") {
				fmt.Printf("state does not match\n")
				close(codeChan)
				wg.Done()
			}

			code := query.Get("code")
			codeChan <- code
			wg.Done()
		}
	}
}
