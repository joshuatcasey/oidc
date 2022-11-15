package printers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

type Printer func(token *jwt.Token, stringToken string) error

func PrintAsClaims(token *jwt.Token, _ string) error {
	tokenClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("cannot access claims from token")
	}

	for key, value := range tokenClaims {
		fmt.Printf("%s=%+v\n", key, value)
	}

	return nil
}

func PrintClaimsAsJson(_ *jwt.Token, token string) error {
	claims := strings.Split(token, ".")[1]

	decodedClaims, err := base64.RawURLEncoding.DecodeString(claims)
	if err != nil {
		return fmt.Errorf("cannot base64 decode claims segment: %w", err)
	}

	buffer := bytes.NewBuffer(nil)

	err = json.Indent(buffer, decodedClaims, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot perform json indent: %w", err)
	}

	fmt.Println(buffer.String())

	return nil
}

func PrintRaw(_ *jwt.Token, token string) error {
	fmt.Println(token)
	return nil
}

func PrintJwtIo(_ *jwt.Token, token string) error {
	fmt.Printf("https://jwt.io/#debugger-io?token=%s\n", token)
	return nil
}
