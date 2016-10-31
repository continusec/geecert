/*

Copyright 2016 Continusec Pty Ltd

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/hydrogen18/stoppableListener"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/pkg/browser"

	"github.com/continusec/geecert"
	pb "github.com/continusec/geecert/sso"

	"golang.org/x/crypto/ssh"
	context "golang.org/x/net/context"

	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
)

const (
	// Used for pre-check validation
	HostedDomain = "yourdomain.com"

	// Client ID is managed in this Google: https://console.developers.google.com/
	ClientID = "xxxxxxx.apps.googleusercontent.com"

	// Note, despite the name, this is not really a secret nor intended to be.
	ClientSecret = "yyyyyyyy"
)

const (
	AuthURI  = "https://accounts.google.com/o/oauth2/auth"
	TokenURI = "https://accounts.google.com/o/oauth2/token"
	CertURL  = "https://www.googleapis.com/oauth2/v1/certs"

	RedirectOOB       = "urn:ietf:wg:oauth:2.0:oob"
	RedirectLocalhost = "http://localhost"

	CredentialCache = ".geecerttoken"
)

const (
	DefaultCertPem = `-----BEGIN CERTIFICATE-----
your server TLS certificate
-----END CERTIFICATE-----
`

	DefaultServer = "sso.yourserver.com:10000"
)

var (
	ErrUserDenied     = errors.New("User clicked deny.")
	ErrInvalidIDToken = errors.New("ErrInvalidIDToken")
)

var (
	OverrideMachinePolicy = false
	OverrideGrpcSecurity  = false
	UseSystemCaFromCert   = false
	ServerHostPort        = ""
	ServerCertificatePath = ""
)

// Try to launch a browser, redirect to local server etc etc
// Return code, redirect URI, error
func DoBrowserDance() (string, string, error) {
	// Find a free port number
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return "", "", err
	}

	// Bind a listener
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return "", "", err
	}

	// Make it stoppable
	stoppable, err := stoppableListener.New(listener)
	if err != nil {
		return "", "", err
	}

	// Get the post out
	port := listener.Addr().(*net.TCPAddr).Port

	// Construct the redirect URL
	redir := RedirectLocalhost + ":" + strconv.Itoa(port)

	// Send the user there
	urlToVisit := AuthURI + "?" + url.Values{
		"scope":         {"email"},
		"redirect_uri":  {redir},
		"response_type": {"code"},
		"client_id":     {ClientID},
	}.Encode()

	err = browser.OpenURL(urlToVisit)
	if err != nil {
		return "", "", err
	}

	fmt.Println(`Please click the "Allow" button in your browser to authorize our SSO tool.`)

	// Wait for the server to get the code
	var code string
	err = http.Serve(stoppable, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := r.FormValue("code")
		switch {
		case len(c) > 0:
			w.Write([]byte("Authorization code received. Please close this window and return to your terminal to complete the process."))
			code = c
			stoppable.Stop()
		case r.FormValue("error") == "access_denied":
			w.Write([]byte("We'll miss you. Please close this window and return to your terminal."))
			stoppable.Stop()
		default:
			w.Write([]byte("Error - please try again."))
		}
	}))
	switch err {
	case nil:
		// pass
	case stoppableListener.StoppedError:
		// pass
	default:
		return "", "", err
	}

	if len(code) < 1 {
		return "", "", ErrUserDenied
	}

	log.Print("Authorization code received.")

	return code, redir, nil
}

func DoOOBDance() (string, string, error) {
	// Send the user there
	urlToVisit := AuthURI + "?" + url.Values{
		"scope":         {"email"},
		"redirect_uri":  {RedirectOOB},
		"response_type": {"code"},
		"client_id":     {ClientID},
	}.Encode()

	fmt.Printf("Please visit (in your browser):\n%s\n\nAnd then paste the code received here: ", urlToVisit)

	// If we don't have one, then prompt for it
	var code string
	for len(code) < 1 {
		_, err := fmt.Scanln(&code)
		if err != nil {
			return "", "", err
		}
	}

	return code, RedirectOOB, nil
}

func SwapCodeForTokens(code, redir string) (*CachedCreds, error) {
	log.Print("Exchanging authorization code for long-lived credentials.")

	// Now we have an authorization code, exchange this for the good stuff
	resp, err := http.PostForm(TokenURI, url.Values{
		"code":          {code},
		"client_id":     {ClientID},
		"client_secret": {ClientSecret},
		"redirect_uri":  {redir},
		"grant_type":    {"authorization_code"},
	})
	if err != nil {
		return nil, err
	}

	// Always read body, even if not 200 as it can contain info about the err
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Fail if not OK
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Unexpected server response: " + resp.Status + " " + string(body))
	}

	var creds CachedCreds
	err = json.Unmarshal(body, &creds)
	if err != nil {
		return nil, err
	}

	log.Print("Received long-lived credentials.")

	return &creds, nil
}

func SwapRefreshForTokens(refreshToken string) (*CachedCreds, error) {
	log.Print("Sending refresh token for short-lived credentials.")

	// Now we have an authorization code, exchange this for the good stuff
	resp, err := http.PostForm(TokenURI, url.Values{
		"refresh_token": {refreshToken},
		"client_id":     {ClientID},
		"client_secret": {ClientSecret},
		"grant_type":    {"refresh_token"},
	})
	if err != nil {
		return nil, err
	}

	// Always read body, even if not 200 as it can contain info about the err
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Fail if not OK
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Unexpected server response: " + resp.Status + " " + string(body))
	}

	var creds CachedCreds
	err = json.Unmarshal(body, &creds)
	if err != nil {
		return nil, err
	}

	// Refresh token is not return to us
	creds.RefreshToken = refreshToken

	log.Print("Received new short-lived credentials.")

	return &creds, nil
}

type CachedCreds struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

// Prompt user to
func Reauthorize(path string) error {
	// First try the browser dance as it's easier for the user
	code, redir, err := DoBrowserDance()
	switch err {
	case nil:
		// yay, pass!
	case ErrUserDenied:
		return err
	default:
		// Fall back to OOB dane
		code, redir, err = DoOOBDance()
	}
	if err != nil {
		return err
	}

	// Swap authorization code for tokens
	creds, err := SwapCodeForTokens(code, redir)
	if err != nil {
		return err
	}

	// Save creds off.
	err = SaveCreds(path, creds)
	if err != nil {
		return err
	}

	// All good
	return nil
}

func LoadCreds(path string) (*CachedCreds, error) {
	body, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var creds CachedCreds
	err = json.Unmarshal(body, &creds)
	if err != nil {
		return nil, err
	}

	return &creds, nil
}

func SaveCreds(path string, creds *CachedCreds) error {
	body, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(path, body, 0600)
	if err != nil {
		return err
	}

	log.Print("Saved credentials to ", path)
	return nil
}

func FetchCerts(idToken string, sshDir string) error {
	log.Println("Generating new private key.")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	ourPubKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	ourPubKeyString := base64.StdEncoding.EncodeToString(ourPubKey.Marshal())

	// Get certs
	var dialOptions []grpc.DialOption
	if OverrideGrpcSecurity {
		// use system CA pool but disable cert validation
		log.Println("WARNING: Disabling TLS authentication when connecting to SSO gRPC server")
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	} else if len(ServerCertificatePath) > 0 {
		tc, err := credentials.NewClientTLSFromFile(ServerCertificatePath, "")
		if err != nil {
			return err
		}
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(tc))
	} else if UseSystemCaFromCert {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))) // uses the system CA pool
	} else {
		// use baked in cert
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM([]byte(DefaultCertPem)) {
			return errors.New("Unable to undertand baked-in cert.")
		}
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: cp})))
	}

	conn, err := grpc.Dial(ServerHostPort, dialOptions...)
	if err != nil {
		return err
	}
	defer conn.Close()
	client := pb.NewGeeCertServerClient(conn)

	log.Println("Requesting fresh certificates...")
	resp, err := client.GetSSHCerts(context.Background(), &pb.SSHCertsRequest{
		IdToken:   idToken,
		PublicKey: ourPubKeyString,
	})
	if err != nil {
		return err
	}

	if resp.Status != 0 {
		return errors.New(fmt.Sprintf("Bad response form server: %#v", resp))
	}

	log.Println("Received new certificates from server.")

	// Create ssh dir if not exists
	_, err = os.Stat(sshDir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("Creating SSH config directory.")
			err = os.Mkdir(sshDir, 0700)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	log.Println("Writing new private key.")
	err = SafeSave(filepath.Join(sshDir, "id_geecert_shortlived_rsa"), pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	), 0600)
	if err != nil {
		return err
	}

	// And public key too, not that it should be needed in theory, but SSH moans if it isn't there.
	// Works in openssh 6.9. Broken in 7.2. Patch has been submitted to openssh team.
	err = SafeSave(filepath.Join(sshDir, "id_geecert_shortlived_rsa.pub"), []byte("ssh-rsa "+ourPubKeyString+" ignorethiscomment\n"), 0644)
	if err != nil {
		return err
	}

	log.Println("Installing new certificate. For more info, run: ssh-keygen -Lf ~/.ssh/id_geecert_shortlived_rsa-cert.pub")
	err = SafeSave(filepath.Join(sshDir, "id_geecert_shortlived_rsa-cert.pub"), []byte(resp.Certificate), 0644)
	if err != nil {
		return err
	}

	// Update known hosts
	err = ReplaceSectionOfFile("GEECERT-CA", filepath.Join(sshDir, "known_hosts"), resp.CertificateAuthorities, 0644, "Updating known_hosts certificate authorities.")
	if err != nil {
		return err
	}

	// Update SSH config
	cnf := make([]string, len(resp.Config))
	for i, line := range resp.Config {
		cnf[i] = strings.Replace(line, "$CERTNAME", filepath.Join(sshDir, "id_geecert_shortlived_rsa"), -1)
	}
	err = ReplaceSectionOfFile("GEECERT-CA", filepath.Join(sshDir, "config"), cnf, 0644, "Updating ssh config file to use certificates.")
	if err != nil {
		return err
	}

	return nil
}

/* Deletes section with name:

# AUTOGENERATED:BEGIN:name
...
# AUTOGENERATED:END:name

and adds new section at end with same.
*/
func ReplaceSectionOfFile(name string, path string, lines []string, perm os.FileMode, messageIfChanged string) error {
	startMarker := "# AUTOGENERATED:BEGIN:" + name
	endMarker := "# AUTOGENERATED:END:" + name

	// Read contents of old file
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) { // it's OK if it doesn't exist
			contents = nil
		} else {
			return err
		}
	}

	// Copy contents to buffer, skipping over our section
	var output []string
	include := true
	for _, line := range strings.Split(string(contents), "\n") {
		if strings.HasPrefix(line, startMarker) {
			include = false
		} else if strings.HasPrefix(line, endMarker) {
			include = true
		} else {
			if include {
				output = append(output, line)
			}
		}
	}

	// Remove any trailing empty lines
	for len(output) > 0 && len(output[len(output)-1]) == 0 {
		output = output[:len(output)-1]
	}

	// If we have a section to append, append it
	if len(lines) > 0 {
		output = append(output, "")
		output = append(output, startMarker+" - DO NOT EDIT BETWEEN MARKERS!")
		output = append(output, lines...)
		output = append(output, endMarker+" - DO NOT EDIT BETWEEN MARKERS!")
	}

	// Always finish with a new line
	output = append(output, "")

	// Only log and write if we've changed.
	newContents := []byte(strings.Join(output, "\n"))
	if !bytes.Equal(contents, newContents) {
		// Save it out
		log.Println(messageIfChanged)
		err = SafeSave(path, newContents, perm)
		if err != nil {
			return err
		}
	}

	return nil
}

func SafeSave(path string, contents []byte, perm os.FileMode) error {
	pathToNew := path + ".tmpfornew"
	err := ioutil.WriteFile(pathToNew, contents, perm)
	if err != nil {
		return err
	}
	err = os.Rename(pathToNew, path)
	if err != nil {
		return err
	}
	return nil
}

// We can use this to soft-enforce only giving certificates out if reasonable precautions
// are in place in the client device, e.g. enforce full disk encryption with machine passcode.
func ValidateMachineIsSuitable() error {
	// TODO: remove ability to do the following
	if OverrideMachinePolicy {
		log.Println("WARNING: Overriding machine policy.")
		return nil
	}

	switch runtime.GOOS {
	case "darwin":
		// on Mac, require full disk encryption be enabled
		out, err := exec.Command("fdesetup", "status").Output()
		if err != nil {
			return err
		}

		if strings.Index(string(out), "FileVault is On") < 0 {
			log.Fatal("FileVault must be enabled if you want SSH certificates. Please enable and then retry (or, re-run with --override_machine_policy)")
		}

		return nil
	default:
		// for now, allow
		return nil
	}
}

func main() {
	flag.StringVar(&ServerHostPort, "server", DefaultServer, "Address:port of the server to connect to")
	flag.StringVar(&ServerCertificatePath, "server_cert", "", "Certificate expected from the server for TLS, overrides default in binary")
	flag.BoolVar(&OverrideMachinePolicy, "override_machine_policy", false, "Please don't use this.")
	flag.BoolVar(&OverrideGrpcSecurity, "allow_insecure_connect_to_sso_server", false, "Please don't use this.")
	flag.BoolVar(&UseSystemCaFromCert, "server_cert_from_real_ca", false, "Use system CA for server cert.")
	flag.Parse()

	err := ValidateMachineIsSuitable()
	if err != nil {
		log.Fatal("Error:", err)
	}

	hd, err := homedir.Dir()
	if err != nil {
		log.Fatal("Error:", err)
	}
	path := filepath.Join(hd, CredentialCache)

	// First, try to load creds, and if we have none, go ahead and authorize us
	creds, err := LoadCreds(path)
	if err != nil {
		err = Reauthorize(path)
		if err != nil {
			log.Fatal("Error:", err)
		}
		creds, err = LoadCreds(path)
		if err != nil {
			log.Fatal("Error:", err)
		}
	}

	// Now that we have creds, try to get a valid ID token refreshing if needed
	email, err := geecert.ValidateIDToken(creds.IDToken, ClientID, HostedDomain)
	if err != nil {
		creds, err = SwapRefreshForTokens(creds.RefreshToken)
		if err != nil {
			log.Fatal("Error:", err)
		}
		err = SaveCreds(path, creds)
		if err != nil {
			log.Fatal("Error:", err)
		}
		email, err = geecert.ValidateIDToken(creds.IDToken, ClientID, HostedDomain)
		if err != nil {
			log.Fatal("Error:", err)
		}
	}

	log.Print("Have valid ID token for:", email)
	err = FetchCerts(creds.IDToken, filepath.Join(hd, ".ssh"))
	if err != nil {
		log.Fatal("Error:", err)
	}
}
