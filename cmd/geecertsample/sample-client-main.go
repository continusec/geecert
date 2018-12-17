/*

Copyright 2018 Continusec Pty Ltd

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
	"flag"
	"log"

	"github.com/continusec/geecert"
)

// To create your own app, copy this file, hard-code the pieces that you want, and
// add as flags anything that you want your users to be able to override.
var LocalConfiguration = geecert.ClientAppConfiguration{
	HostedDomain: "orgname.com",

	// Client ID is managed in this Google project: https://console.developers.google.com/

	ClientID: "xxxxxxx.apps.googleusercontent.com",

	ClientNotSoSecret: "yyyyyyy",

	GRPCPEMCertificate: `-----BEGIN CERTIFICATE-----
MIIF...RI=
-----END CERTIFICATE-----
`,

	CredentialFileName: ".orgnamesso",
	ShortlivedKeyName:  "id_orgname_shortlived_rsa",
	SectionIdentifier:  "ORGNAME-CA",

	// Other fields are specified via defaults in flags below
}

func main() {
	flag.StringVar(&LocalConfiguration.GRPCServer, "server", "sso.orgname.com:10000", "Address:port of the server to connect to")
	flag.StringVar(&LocalConfiguration.GRPCPEMCertificatePath, "server_cert", "", "Certificate expected from the server for TLS, overrides default in binary")
	flag.BoolVar(&LocalConfiguration.OverrideMachinePolicy, "override_machine_policy", false, "Please don't use this.")
	flag.BoolVar(&LocalConfiguration.OverrideGrpcSecurity, "allow_insecure_connect_to_sso_server", false, "Please don't use this.")
	flag.BoolVar(&LocalConfiguration.UseSystemCaForCert, "server_cert_from_real_ca", false, "Use system CA for server cert.")
	flag.Parse()

	err := geecert.ProcessClient(&LocalConfiguration)
	if err != nil {
		log.Fatal(err)
	}
}
