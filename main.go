package main

import (
	"fmt"
        "os"
        "os/exec"
        "runtime"
        "github.com/alexflint/go-arg"
        "io"
        "net/http"
        "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
        "gopkg.in/ini.v1"
        "encoding/json"
        "time"
        "github.com/zalando/go-keyring"
        "log"
)

type Config struct {
  AccountId  string
  IDPArn     string
  LoginUrl   string
}

type Args struct {
  Profile     string   `arg:"positional,required"`
  Role        string   `arg:"positional,required"`
  OutputMode  string   `arg:"--output,-o" default:"creds-file"`
  Duration    int64    `default:"43200"`
  Force       bool     `arg:"-f"`
}

type CredentialsProcessOutput struct {
  Version         int
  AccessKeyId     string
  SecretAccessKey string
  SessionToken    string
  Expiration      string
}

var config Config
var args   Args

var keyringService string = "aws-auth"

var KeyringGet = keyring.Get
var KeyringSet = keyring.Set

func getEnv(key, defaultValue string) string {
    value := os.Getenv(key)
    if len(value) == 0 {
        return defaultValue
    }
    return value
}

func main() {
  arg.MustParse(&args)

  homeDir, err := os.UserHomeDir()

  config_file   := getEnv("AWS_AUTH_CONFIG_FILE", homeDir + "/.aws/config")
  cert_file     := getEnv("AWS_AUTH_CERT_FILE", homeDir + "/.aws/localhost.cert")
  cert_key_file := getEnv("AWS_AUTH_CERT_KEY_FILE", homeDir + "/.aws/localhost.key")

  cfg, err := ini.Load(config_file)
  if err != nil {
    log.Fatal(err)
  }

  config.AccountId  = cfg.Section("profile " + args.Profile).Key("account_id").String()
  config.IDPArn     = cfg.Section("profile " + args.Profile).Key("idp_arn").String()
  config.LoginUrl   = cfg.Section("profile " + args.Profile).Key("login_url").String()

  valid, _ := getActiveSessionInfo(keyringService, args.Profile, args.Role)

  if valid && !args.Force {
    outputCredentials(args.OutputMode, args.Profile, args.Role)
    return
  }

  http.HandleFunc("/saml", postSaml)

  go func() {
    err := http.ListenAndServeTLS(":12200", cert_file, cert_key_file, nil)
    if err != nil {
      log.Println("I SHIT MYSELF")
      os.Exit(1)
    }
  }()

  log.Println("Opening url: (" + config.LoginUrl + ") in a browser")
  openbrowser(config.LoginUrl)

  time.Sleep(10 * time.Second)
  log.Println("No response from Auth0 after 10 seconds, check your connectivity to auth0 and your configuration")
}

func postSaml(w http.ResponseWriter, r *http.Request) {
  io.WriteString(w, `<!doctype html>`)
  io.WriteString(w, `<html lang="en">`)
  io.WriteString(w, `  <head>`)
  io.WriteString(w, `    <title>SAML Login for AWS SDK/CLI</title>`)
  io.WriteString(w, `    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css" integrity="sha384-HSMxcRTRxnN+Bdg0JdbxYKrThecOKuH5zCYotlSAcp1+c8xmyTe9GYg1l9a69psu" crossorigin="anonymous">`)
  io.WriteString(w, `  </head>`)
  io.WriteString(w, `  <body style="margin-top: 10px">`)

  err := r.ParseForm()
  if err != nil {
    log.Fatal("Error Parsing response")
  }
  
  if r.Form.Has("SAMLResponse") {
    samlResponse := r.Form.Get("SAMLResponse");
    io.WriteString(w, `        <div class="center-block text-center alert alert-success" style="font-size: 15px"><b>Success!</b> You've been authenticated. You can close this browser page and go back to your terminal.</div>`)
    io.WriteString(w, `  </body>`)
    io.WriteString(w, `</html>`)

    w.WriteHeader(http.StatusCreated)
    if f, ok := w.(http.Flusher); ok {
        f.Flush()
    }
    awsAuth(samlResponse);
    outputCredentials(args.OutputMode, args.Profile, args.Role)

    os.Exit(0)
  } else {
    rawBody, _ := io.ReadAll(r.Body)
    io.WriteString(w, `        <div class="center-block text-center alert alert-danger" style="font-size: 15px"><b>Error!</b> There was a problem authenticating. The response was as follows.</div>`)
    io.WriteString(w, `        <div class="center-block text-center alert alert-danger" style="font-size: 15px">` + string(rawBody) + `</div>`)
    io.WriteString(w, `  </body>`)
    io.WriteString(w, `</html>`)

    http.Error(w, http.StatusText(400), 400)
    if f, ok := w.(http.Flusher); ok {
        f.Flush()
    }

    os.Exit(1)
  }

  
}

func awsAuth(samlResponse string) {
  svc := sts.New(session.New())

  input := &sts.AssumeRoleWithSAMLInput{
    DurationSeconds: aws.Int64(args.Duration),
    PrincipalArn:    aws.String(config.IDPArn),
    RoleArn:         aws.String("arn:aws:iam::" + config.AccountId + ":role/" + args.Role),
    SAMLAssertion:   aws.String(samlResponse),
  }

  result, err := svc.AssumeRoleWithSAML(input)

  if err != nil {
    log.Fatal(err)
  }

  log.Println("Successfully Authenticated!")

  session := &CredentialsProcessOutput{
    Version: 1,
    AccessKeyId: *result.Credentials.AccessKeyId,
    SecretAccessKey: *result.Credentials.SecretAccessKey,
    SessionToken: *result.Credentials.SessionToken,
    Expiration: result.Credentials.Expiration.Format(time.RFC3339),
  }

  setSessionInfo(keyringService, args.Profile, args.Role, *session)

}

func getActiveSessionInfo(service string, environment string, role string) (bool, *CredentialsProcessOutput) {
  user    := environment + "|" + role

  // get session from keyring if it exists
  secret, err := KeyringGet(service, user)

  if err == keyring.ErrNotFound {
    return false, &CredentialsProcessOutput{}
  } else if err != nil {
    log.Fatal(err)
  }

  var session CredentialsProcessOutput

  json.Unmarshal([]byte(secret), &session)

  expiration, err := time.Parse(time.RFC3339, session.Expiration)

  if time.Until(expiration).Minutes() < 20 {
    return false, &CredentialsProcessOutput{}
  }

  return true, &session
}

func setSessionInfo(service, environment string, role string, session CredentialsProcessOutput) {
  user    := environment + "|" + role

  session_json, _ := json.MarshalIndent(session, "", "  ")

  // set password
  err := KeyringSet(service, user, string(session_json))
  if err != nil {
    log.Fatal(err)
  }

  log.Println("Session saved to keyring")
}

func openbrowser(url string) {
  var err error

  switch runtime.GOOS {
    case "linux":
      err = exec.Command("xdg-open", url).Start()
    case "windows":
      err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
    case "darwin":
      err = exec.Command("open", url).Start()
    default:
      err = fmt.Errorf("unsupported platform")
  }

  if err != nil {
    log.Fatal(err)
  }
}

func outputCredentials(mode string, environment string, role string) {
  valid, session := getActiveSessionInfo(keyringService, args.Profile, args.Role)

  if !valid {
    log.Fatal("Failed to retrieve valid credentials from keyring")
  }

  switch mode {
    case "creds-file":
      outputIni("default", environment, role, *session)
    case "json":
      outputJson(*session)
    default:
      log.Fatal("Unknown output mode: " + mode)
  }
}

func outputIni(profileName string, environment string, role string, session CredentialsProcessOutput) {

  homeDir, err := os.UserHomeDir()
  credsFile := homeDir + "/.aws/credentials"

  creds, err := ini.Load(credsFile)
  if err != nil {
    log.Fatal(err)
  }

  creds.Section(profileName).Key("aws_access_key_id").SetValue(session.AccessKeyId)
  creds.Section(profileName).Key("aws_secret_access_key").SetValue(session.SecretAccessKey)
  creds.Section(profileName).Key("aws_session_token").SetValue(session.SessionToken)
  creds.Section(profileName).Key("aws_token_expiration").SetValue(session.Expiration)
  creds.Section(profileName).Key("aws_account_alias").SetValue(environment)
  creds.Section(profileName).Key("aws_role_name").SetValue(role)
  creds.SaveTo(credsFile)
}

func outputJson(session CredentialsProcessOutput) {
  session_json, _ := json.MarshalIndent(session, "", "  ")

  fmt.Println(string(session_json))
}
