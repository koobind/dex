package koobind

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
	proto "github.com/koobind/koobind/koomgr/apis/proto/auth/v2"
	"net"
	"net/http"
	"os"
	"time"
)

type Config struct {
	Url                string   `json:"Url"`
	RootCAs            []string `json:"rootCAs"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
	LoginPrompt        string   `json:"loginPrompt"`
}

type koobindConnector struct {
	Config
	logger     log.Logger
	httpClient *http.Client
}

var (
	_ connector.PasswordConnector = (*koobindConnector)(nil)
)

func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	logger.Infof("koobind Open(id:%s url:%s)", id, c.Url)
	conn := &koobindConnector{
		Config: *c,
		logger: logger,
	}
	var err error
	conn.httpClient, err = newHTTPClient(c.RootCAs, c.InsecureSkipVerify)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Copied from oauth.go connector
func newHTTPClient(rootCAs []string, insecureSkipVerify bool) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	tlsConfig := tls.Config{RootCAs: pool, InsecureSkipVerify: insecureSkipVerify}
	for _, rootCA := range rootCAs {
		rootCABytes, err := os.ReadFile(rootCA)
		if err != nil {
			return nil, fmt.Errorf("failed to read root-ca: %v", err)
		}
		if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCABytes) {
			return nil, fmt.Errorf("no certs found in root CA file %q", rootCA)
		}
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, nil
}

func (k *koobindConnector) Prompt() string {
	//k.logger.Infof("koobindConnector.Prompt()")
	if k.LoginPrompt == "" {
		return "Koobind Login"
	} else {
		return k.LoginPrompt
	}
}

func (k *koobindConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error) {
	k.logger.Infof("koobindConnector.Login(%s, %s)", username, password)
	body, err := json.Marshal(proto.LoginRequest{
		Login:    username,
		Password: password,
	})
	if err != nil {
		return connector.Identity{}, false, fmt.Errorf("unable to marshal dexLoginRequest (login:'%s'): %w", username, err)
	}
	request, err := http.NewRequest("POST", k.Url+proto.LoginUrlPath, bytes.NewBuffer(body))
	if err != nil {
		return connector.Identity{}, false, fmt.Errorf("unable build http request (login:'%s'): %w", username, err)
	}
	response, err := k.httpClient.Do(request)
	if err != nil {
		return connector.Identity{}, false, fmt.Errorf("error while calling koobind server (login:'%s'): %w", username, err)
	}
	if response.StatusCode == http.StatusUnauthorized {
		return connector.Identity{}, false, nil
	}
	if response.StatusCode != http.StatusOK {
		return connector.Identity{}, false, fmt.Errorf("invalid status code from koobind server:%d", response.StatusCode)
	}
	loginResponse := proto.LoginResponse{}
	err = json.NewDecoder(response.Body).Decode(&loginResponse)
	if err != nil {
		return connector.Identity{}, false, fmt.Errorf("error while decoding response from koobind server:%w", err)

	}
	identity = connector.Identity{
		UserID:        loginResponse.Uid,
		Username:      loginResponse.Username,
		EmailVerified: loginResponse.EmailVerified,
		Groups:        loginResponse.Groups,
		ConnectorData: []byte(loginResponse.Token),
	}
	if len(loginResponse.Emails) > 0 {
		identity.Email = loginResponse.Emails[0]
	}
	if len(loginResponse.CommonNames) > 0 {
		identity.PreferredUsername = loginResponse.CommonNames[0]
	}
	return identity, true, nil
}
