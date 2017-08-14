# Single Sign On from G-Suite (Google Apps) to SSH

The following provides an end-to-end SSO solution that allows using Google Apps sign-in (where things like 2-factor can be enforced) to allow SSH access to your hosts using the standard SSH command line tools.

## Deployment

The server is expected to be built and and run 'as-is', as its configuration is controlled by a configuration file, described below.

For the client we expect your server administrator to build a custom binary that comes pre-baked with your organizations configuration, by copying the sample harness, replacing with your configuration values, and building a binary that you distribute to your users.

## Building from source

Both client and server are written in Go. Amongst other things, an advantage of writing this in Go means that it is easy to build and distribute a single static binary with no dependencies which is useful for distributing client login tool within your organization.

First, install go <https://golang.org/dl/> and set an appropriate `GOPATH` in your profile, for example:

```bash
cat >> ~/.bash_profile <<EOF
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$PATH
EOF
source ~/.bash_profile
```

Fetch source and build both the client and the server (the `...` is not a typo), can be re-run to fetch updates:

```bash
go get -u github.com/continusec/geecert/cmd/...
```

Verify binaries are built:

```bash
ls $GOPATH/bin
```

Shows:

    geecertsample
    servegeecerts

### Developer notes

If you make any changes to `sso.proto`, run the following to re-generate new Go code (assumes that [protoc](https://github.com/google/protobuf/releases) is installed):

```bash
cd $GOPATH/src/github.com/continusec/geecert
go generate
```

To build and install new server and client after changing Go source, run:

```bash
go install github.com/continusec/geecert/cmd/...
```

## SSO Server

The SSO Server can be built from source assuming a working `golang` install. It does however compile to a single statically linked binary, so once built that binary can be distributed to another machine without needing anything else.

### Running `servegeecerts`

To run `servegeecerts` you first need to configure a valid configuration file. The configuration file is in protobuf text format. See sample configuration file here: [$GOPATH/src/github.com/continusec/geecert/sample\_server\_config.proto](./sample_server_config.proto)

See that file for more information on the options available.

Once a config file is prepared, simply run the server:

```bash
servegeecerts /path/to/config.proto
```

If all is good, you should see:

    2016/10/18 17:14:29 Serving...

Now, go build and run a client to use.

### Host certificates

The CA server has the ability to issue host certificates. If a request is made to: `https://your.server/hostCertificate?host=host.name`, the CA will check to see if the specified hostname is matched as an allowed host (per the server configuration file), and if so, it will attempt to begin an SSH handshake with that server, and sign the public key that it is presented and return that to the caller.

In this manner this endpoint can be easily called by shell scripts in your fleet to self-sign host certificates.

## `geecertsample` client tool

For the client your server administrator needs to configure and build a custom binary that comes pre-baked with your organizations configuration, by copying the sample harness, replacing with your configuration values, and building a binary that you distribute to your users.

To do so, first make sure the source code is available:

```bash
go get -u github.com/continusec/geecert
```

And, then in your project, e.g. in `$GOPATH/src/github.com/you/ssotool/cmd/getmycerts/main.go`:

```go
package main

import (
    "flag"
    "log"

    "github.com/continusec/geecert"
)

var LocalConfiguration = geecert.ClientAppConfiguration{
    HostedDomain: "orgname.com",
    ClientID: "xxxxxxx.apps.googleusercontent.com",
    ClientNotSoSecret: "yyyyyyy",
    GRPCPEMCertificate: `-----BEGIN CERTIFICATE-----
...
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
```

Or similar. Then build it:

```bash
go install github.com/you/ssotool/cmd/getmycerts
```

And run:

```bash
getmycerts
```

(Note, this is intended to be run from an end-client workstation, e.g. your laptop, rather than an intermediate server)

The first time this is run, it will perform an OAuth 2.0 dance with Google to fetch long-lived credentials for your account. If you are running in a nice GUI environment it will launch a browser for you. Otherwise you'll be given a URL to copy/paste.

Then (and on each subsequent run), it will check to see if it has a valid short-lived ID token from Google. If not, it will connect to Google to fetch a new one (which will be granted unless the user (or a domain admin)) revokes access by the SSO tool.

Next it will generate a new key/pair and send the public key and the short lived ID token to the `servegeecerts` that we ran above. The `servegeecerts` will validate the ID token, and then, if appropriate, will generate a new certificate for that public key, and send it back the client.

Finally the client will update a set of config files in `~/.ssh`. Specifically it will:

1. Overwrite `~/.ssh/id_orgname_shortlived_rsa` with the new private key generated.

1. Overwrite `~/.ssh/id_orgname_shortlived_rsa.pub` with the new public key generated.

1. Overwrite `~/.ssh/id_orgname_shortlived_rsa-cert.pub` with the certicate received for that key.

1. Edit `~/known_hosts` to add (and overwrite this section on subsequent runs) this section:

        # AUTOGENERATED:BEGIN:GEECERT - DO NOT EDIT BETWEEN MARKERS!
        @cert-authority *.yourdomain.com sha-rsa AAAAB3NzaC...qZyhLayRUw== GEECERTCA
        # AUTOGENERATED:END:GEECERT- DO NOT EDIT BETWEEN MARKERS!

1. Edit `~/config` to add (and overwrite this section on subsequent runs) this section:

        # AUTOGENERATED:BEGIN:GEECERT - DO NOT EDIT BETWEEN MARKERS!
        Host *.yourdomain.com
            User foo
            IdentityFile ~/.ssh/id_orgname_shortlived_rsa
            IdentitiesOnly yes
            PasswordAuthentication no
        # AUTOGENERATED:END:GEECERT - DO NOT EDIT BETWEEN MARKERS!

This instructs the client to use (and only use) the new certificate, and to trust the same CA for host-based authentication. The config returned here is controlled by the server.

### Tip: Worried about bad things happening to good config

Consider backing up your `~/.ssh` before running the tool if concerned. Alternatively consider running a local git repo until comfortable with what the tool is doing - make it easy to see the differences:

```bash
cd ~/.ssh
git init
git add *
git commit -a -m "Initial commit."
```

## Troubleshooting

### "FileVault must be enabled" error

The client soft-enforces a minimum security profile that should be present on a workstation on in order to receive credentials to production systems. As such, when present on a Mac, if full disk encryption is not enabled, then the client will not run (and other platforms to follow). The intention is to mitigate against theft of a device that contains credentials.

The best way to fix this error is to enabled FileVault. Alternatively, re-run with `--override_machine_policy` (if you choose to leave this option in your binary).

### Deleting cached credentials

If there are errors coming back from the Google server such as `invalid_grant`, try removing the saved credentials and re-authorizing the application.

```bash
rm ~/.orgnamesso
```

Then re-run the tool:

```bash
getmycerts
```

### Revoking access to Google account

To revoke access to your Google account, visit:
<https://security.google.com/settings/security/permissions>

And remove the application that matches your client ID. Note that since the ID Tokens issued by Google are generally for 1 hour, they will continue to be accepted by the SSO server until they timeout.

## Acknowledgements

The author gratefully acknowledges the initial funding for development of this tool by [Androgogic Pty Ltd](http://www.androgogic.com/).
