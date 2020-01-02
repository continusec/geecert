/*

Copyright 2019 Continusec Pty Ltd

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
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang/protobuf/proto"

	"golang.org/x/net/context"

	"github.com/continusec/geecert"
	pb "github.com/continusec/geecert/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"time"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"net/http"

	"golang.org/x/crypto/ssh"
)

type SSOServer struct {
	Config *pb.ServerConfig

	Validator geecert.IDTokenValidator
}

// Generate a host cert for whatever we see
func (s *SSOServer) makeHostCert(w http.ResponseWriter, h string) {
	var certToReturn []byte
	var kt string

	// Derived from ssh.common.supportedHostKeyAlgos with certificate host key types removed
	var supportedHostKeyAlgos = []string{
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA, ssh.KeyAlgoDSA, ssh.KeyAlgoED25519,
	}
	ssh.Dial("tcp", fmt.Sprintf("%s:%d", h, s.Config.SshConnectForPublickeyPort), &ssh.ClientConfig{
		User: "ca",
		Auth: []ssh.AuthMethod{
			ssh.Password("wrongpassignoreme"),
		},
		HostKeyAlgorithms: supportedHostKeyAlgos,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if key == nil {
				return errors.New("no host key")
			}
			caKey, err := LoadPrivateKeyFromPEM(s.Config.CaKeyPath)
			if err != nil {
				return err
			}

			cert, nva, err := CreateHostCertificate(h, key, caKey, time.Duration(s.Config.GenerateCertDurationSeconds)*time.Second)
			if err != nil {
				return err
			}
			kt = key.Type()

			log.Printf("Issued host certificate for %s valid until %s.\n", h, nva.Format(time.RFC3339))

			certToReturn = cert
			return errors.New("fail now please")
		},
	})

	// Ignore error code for above, as we'll definitely fail due to no creds
	if len(certToReturn) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "%s-cert-v01@openssh.com %s %s\n", kt, base64.StdEncoding.EncodeToString(certToReturn), h)
}

func (s *SSOServer) issueHostCertificate(w http.ResponseWriter, r *http.Request) {
	h := r.FormValue("host")
	for _, m := range s.Config.AllowedHosts {
		matched, err := filepath.Match(m, h)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if matched {
			s.makeHostCert(w, h)
			return
		}
	}
	w.WriteHeader(http.StatusBadRequest)
	return
}

func (s *SSOServer) StartHTTP() {
	http.HandleFunc("/hostCertificate", s.issueHostCertificate)
	var err error
	if s.Config.HostSigningTlsPath == "" { // http
		err = http.ListenAndServe(fmt.Sprintf(":%d", s.Config.HttpListenPort), nil)
	} else {
		err = http.ListenAndServeTLS(fmt.Sprintf(":%d", s.Config.HttpListenPort), s.Config.HostSigningTlsPath, s.Config.HostSigningTlsPath, nil)
	}
	if err != nil {
		log.Printf("Error starting HTTP server: %s", err)
	}
}

func (s *SSOServer) GetSSHCerts(ctx context.Context, in *pb.SSHCertsRequest) (*pb.SSHCertsResponse, error) {
	idTokenClaims, err := s.Validator.ValidateIDToken(in.IdToken)
	if err != nil {
		return nil, err
	}

	userConf, ok := s.Config.AllowedUsers[idTokenClaims.EmailAddress]
	if !ok {
		return &pb.SSHCertsResponse{
			Status: pb.ResponseCode_NO_CERTS_ALLOWED,
		}, nil
	}

	rpk, err := base64.StdEncoding.DecodeString(in.PublicKey)
	if err != nil {
		return nil, err
	}

	keyToSign, err := ssh.ParsePublicKey(rpk)
	if err != nil {
		return nil, err
	}

	caKey, err := LoadPrivateKeyFromPEM(s.Config.CaKeyPath)
	if err != nil {
		return nil, err
	}

	ourCAPubKey, err := ssh.NewPublicKey(&caKey.PublicKey)
	if err != nil {
		return nil, err
	}

	// Use map to de-dupe
	principals := make(map[string]interface{})
	knownHosts := make(map[string]interface{})
	perms := make(map[string]string)
	var sshConfig []string
	for _, up := range userConf.Profiles {
		p, ok := s.Config.UserProfiles[up]
		if !ok {
			log.Printf("Warning, profile not found for user (ignoring): %s", up)
			continue
		}
		for _, pp := range p.Principals {
			principals[pp] = nil
		}
		for _, pp := range p.KnownHosts {
			knownHosts[pp] = nil
		}
		for k, v := range p.CertPermissions {
			perms[k] = v // last one wins - usually these are blank anyway
		}
		sshConfig = append(sshConfig, p.SshConfigLines...)
	}
	var principalList []string
	for key := range principals {
		principalList = append(principalList, key)
	}
	var knownHostsFile []string
	for kh := range knownHosts {
		knownHostsFile = append(knownHostsFile, fmt.Sprintf("@cert-authority %s ssh-rsa %s %s",
			kh,
			base64.StdEncoding.EncodeToString(ourCAPubKey.Marshal()),
			s.Config.CaComment,
		))
	}

	cert, nva, err := CreateUserCertificate(principalList, idTokenClaims.EmailAddress, keyToSign, caKey, time.Duration(s.Config.GenerateCertDurationSeconds)*time.Second, perms)
	if err != nil {
		return nil, err
	}

	log.Printf("Issued certificate to %s valid until %s.\n", idTokenClaims.EmailAddress, nva.Format(time.RFC3339))

	return &pb.SSHCertsResponse{
		Status:                 pb.ResponseCode_OK,
		Certificate:            fmt.Sprintf("ssh-rsa-cert-v01@openssh.com %s %s\n", base64.StdEncoding.EncodeToString(cert), idTokenClaims.EmailAddress),
		CertificateAuthorities: knownHostsFile,
		Config:                 sshConfig,
	}, nil
}

func LoadPrivateKeyFromPEM(path string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Decode PEM
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("Bad PEM")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("Unexpected block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func CreateHostCertificate(hostname string, keyToSign ssh.PublicKey, signingKey *rsa.PrivateKey, duration time.Duration) ([]byte, *time.Time, error) {
	signer, err := ssh.NewSignerFromKey(signingKey)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	end := now.Add(duration)
	cert := ssh.Certificate{
		Key:             keyToSign,
		CertType:        ssh.HostCert,
		KeyId:           hostname,
		ValidPrincipals: []string{hostname},
		ValidAfter:      uint64(now.Unix()),
		ValidBefore:     uint64(end.Unix()),
	}
	err = cert.SignCert(rand.Reader, signer)
	if err != nil {
		return nil, nil, err
	}
	return cert.Marshal(), &end, nil
}

func CreateUserCertificate(usernames []string, emailAddress string, keyToSign ssh.PublicKey, signingKey *rsa.PrivateKey, duration time.Duration, perms map[string]string) ([]byte, *time.Time, error) {
	signer, err := ssh.NewSignerFromKey(signingKey)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	end := now.Add(duration)
	cert := ssh.Certificate{
		Key:             keyToSign,
		CertType:        ssh.UserCert,
		KeyId:           strings.Join(usernames, "/") + " (for " + emailAddress + ")",
		ValidPrincipals: usernames,
		ValidAfter:      uint64(now.Unix()),
		ValidBefore:     uint64(end.Unix()),
		Permissions: ssh.Permissions{
			Extensions: perms,
		},
	}
	err = cert.SignCert(rand.Reader, signer)
	if err != nil {
		return nil, nil, err
	}
	return cert.Marshal(), &end, nil
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Please specify a config file for the server to use.")
	}

	confData, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	conf := &pb.ServerConfig{}
	err = proto.UnmarshalText(string(confData), conf)
	if err != nil {
		log.Fatal(err)
	}

	tc, err := credentials.NewServerTLSFromFile(conf.ServerCertPath, conf.ServerKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", conf.ListenPort))
	if err != nil {
		log.Fatal(err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(tc))
	sso := &SSOServer{
		Config: conf,
		Validator: &geecert.OIDCIDTokenValidator{
			ConfigurationURL: conf.OidcConfigurationUrl,
			ClientID:         conf.AllowedClientIdForIdToken,
			HostedDomain:     conf.AllowedDomainForIdToken,

			SkipEmailVerified:        conf.SkipEmailVerified,
			AudienceInAppID:          conf.LookForAudienceInAppId,
			GetHostedDomainFromEmail: conf.LookForHostedDomainInEmail,
		},
	}
	pb.RegisterGeeCertServerServer(grpcServer, sso)

	log.Println("Serving...")
	if conf.HttpListenPort != 0 {
		go sso.StartHTTP()
	}

	grpcServer.Serve(lis)
}
