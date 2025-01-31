package main

import (
    "testing"
    "time"
    "github.com/zalando/go-keyring"
    "github.com/stretchr/testify/assert"
    "github.com/prashantv/gostub"
)

var testKeyringService string = "aws-auth-unit-test"

func TestGetActiveSessionInfoWithNoActiveSession(t *testing.T) {
    stubs := gostub.StubFunc(&KeyringGet, "", keyring.ErrNotFound)
    defer stubs.Reset()

    is_active, _ := getActiveSessionInfo(testKeyringService, "staging", "readonly")

    assert.False(t, is_active, "An Active Session was returned when keyring was empty")

   
}

func TestGetActiveSessionInfoExpiredSession(t *testing.T) {
    stubs := gostub.StubFunc(&KeyringGet, `{
        "Version": 1,
        "AccessKeyId": "DUMMY",
        "SecretAccessKey": "DUMMYSECRET",
        "SessionToken": "DUMMYSESSIONTOKEN",
        "Expiration": "1970-01-01T00:00:00Z"
      }`,
      nil)
    defer stubs.Reset()

    is_active, _ := getActiveSessionInfo(testKeyringService, "staging", "readonly")

    assert.False(t, is_active, "An Active Session when the session stored in the keyring had expired")
}

func TestGetActiveSessionInfoValidActiveSession(t *testing.T) {
    stubs := gostub.StubFunc(&KeyringGet, `{
        "Version": 1,
        "AccessKeyId": "DUMMY",
        "SecretAccessKey": "DUMMYSECRET",
        "SessionToken": "DUMMYSESSIONTOKEN",
        "Expiration": "3000-01-01T00:00:00Z"
      }`,
      nil)
    defer stubs.Reset()

    is_active, session := getActiveSessionInfo(testKeyringService, "staging", "readonly")

    assert.True(t, is_active, "No active session returned but keyring should have contained one")
    assert.Equal(t, session.Version,         1,                   "Session Version not set correctly")
    assert.Equal(t, session.AccessKeyId,     "DUMMY",             "Access Key Id returned with incorrect value")
    assert.Equal(t, session.SecretAccessKey, "DUMMYSECRET",       "Secret Access Key returned with incorrect value")
    assert.Equal(t, session.SessionToken,    "DUMMYSESSIONTOKEN", "Session Token returned with incorrect value")

    expiration, err := time.Parse(time.RFC3339, session.Expiration)
    assert.Empty(t, err, "Failed to parse returned session expiration date")

    expected_expiration, err := time.Parse(time.RFC3339, "3000-01-01T00:00:00Z")
    assert.Equal(t, expiration, expected_expiration, "Expiration returned with incorrect value")
}
