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
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
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

	"golang.org/x/crypto/ssh"
)

type SSOServer struct {
	Config *pb.ServerConfig
}

func (s *SSOServer) GetSSHCerts(ctx context.Context, in *pb.SSHCertsRequest) (*pb.SSHCertsResponse, error) {
	idTokenClaims, err := geecert.ValidateIDToken(in.IdToken, s.Config.AllowedClientIdForIdToken, s.Config.AllowedDomainForIdToken)
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

	cert, nva, err := CreateUserCertificate(append([]string{userConf.Username}, userConf.ExtraPrincipals...), idTokenClaims.EmailAddress, keyToSign, caKey, time.Duration(s.Config.GenerateCertDurationSeconds)*time.Second, userConf.CertPermissions)
	if err != nil {
		return nil, err
	}

	log.Printf("Issued certificate to %s valid until %s.\n", idTokenClaims.EmailAddress, nva.Format(time.RFC3339))

	return &pb.SSHCertsResponse{
		Status:      pb.ResponseCode_OK,
		Certificate: fmt.Sprintf("ssh-rsa-cert-v01@openssh.com %s %s\n", base64.StdEncoding.EncodeToString(cert), idTokenClaims.EmailAddress),
		CertificateAuthorities: []string{
			fmt.Sprintf("@cert-authority %s ssh-rsa %s %s", s.Config.ClientConfigScope, base64.StdEncoding.EncodeToString(ourCAPubKey.Marshal()), s.Config.CaComment),
		},
		Config: augmentWithIndented([]string{
			"Host " + s.Config.ClientConfigScope,
			"    User " + userConf.Username,
			"    IdentityFile $CERTNAME", // client to replace
			"    IdentitiesOnly yes",
			"    PasswordAuthentication no",
		}, s.Config.AdditionalSshConfigurationLine, "    "),
	}, nil
}

func augmentWithIndented(base []string, additional []string, indent string) []string {
	for _, line := range additional {
		base = append(base, indent+line)
	}
	return base
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
	pb.RegisterGeeCertServerServer(grpcServer, &SSOServer{Config: conf})

	log.Println("Serving...")
	grpcServer.Serve(lis)
}
