## aws-auth
Simple utility for managing aws sessions acquired via IDP SAML provider

*This is a work in progress*
More info and better installation instruction to follow

### Installation ###
Download from the following url
 * [MAC (ARM64)](https://github.com/jimmydavies/aws-auth/actions/runs/13074711744/artifacts/2517230919)

 * Unzip with your favourite unzipping tool
 * Unquarantine the binary `xattr -r -d com.apple.quarantine </path/to/file>`
 * Add to your path

### Configure ###
Add a profile to your aws config file that looks like this
```
[profile <rolename>]
account_id = <my_aws_account_number>
idp_arn    = <arn_of_the_iam_idp_saml_provider>
login_url  = <login_url>
credential_process = <path_to_this_script> <environment> <rolename> -o json
```

### Test ###
`aws-auth -o json <environment> <rolename>`



