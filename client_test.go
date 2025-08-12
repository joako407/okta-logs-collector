package main

import (
	"bytes"
	// "context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/okta/okta-sdk-golang/v5/okta"
	"github.com/stretchr/testify/assert"
)

func TestPrintEvents(t *testing.T) {
	config = &Config{
		oktaURL:          "https://example.okta.com",
		apiKey:           "your-api-key",
		logLevel:         "info",
		lookbackInterval: 24 * time.Hour,
		requestTimeout:   10 * time.Second,
		pollInterval:     5 * time.Second,
	}
	client := NewOktaClient(config)
	assert.NotNil(t, client)

	buf := bytes.NewBuffer(nil)
	setupLogger(buf, config.logLevel)

	now := time.Now()
	isProxy := false

	// Create a sample log event
	// see https://developer.okta.com/docs/reference/api/system-log/#example-logevent-object
	events := []okta.LogEvent{
		{
			Actor: &okta.LogActor{
				AlternateId: okta.PtrString("test@example.com"),
				DisplayName: okta.PtrString("Test User"),
				Id:          okta.PtrString("some-random-id"),
				Type:        okta.PtrString("User"),
			},
			AuthenticationContext: &okta.LogAuthenticationContext{
				AuthenticationStep: okta.PtrInt32(0),
				ExternalSessionId:  okta.PtrString("some-random-id"),
			},
			Client: &okta.LogClient{
				Device: okta.PtrString("Computer"),
				GeographicalContext: &okta.LogGeographicalContext{
					City:    okta.PtrString("New York"),
					Country: okta.PtrString("US"),
					Geolocation: &okta.LogGeolocation{
						Lat: okta.PtrFloat64(40.7128),
						Lon: okta.PtrFloat64(74.0060),
					},
					PostalCode: okta.PtrString("10000"),
					State:      okta.PtrString("NY"),
				},
				Id:        okta.PtrString("some-random-id"),
				IpAddress: okta.PtrString("1.1.1.1"),
				UserAgent: &okta.LogUserAgent{
					Browser:      okta.PtrString("Chrome"),
					Os:           okta.PtrString("Mac OS X"),
					RawUserAgent: okta.PtrString("random-user-agent"),
				},
				Zone: okta.PtrString("null"),
			},
			DebugContext: &okta.LogDebugContext{
				DebugData: map[string]interface{}{
					"authnRequestId":  "some-random-id",
					"dtHash":          "some-random-hash",
					"redirectUri":     "https://example.com/login/sso/oidc",
					"requestId":       "some-random-id",
					"requestUri":      "/oauth2/v1/authorize",
					"threatSuspected": "false",
					"url":             "/oauth2/v1/authorize?client_id=some-random-id&scope=openid+email+profile&response_type=code&redirect_uri=https://example.com/login/sso/oidc&state=some-random-state&code_challenge=some-random-code-challenge&code_challenge_method=S256",
				},
			},
			DisplayMessage:  okta.PtrString("User attempted unauthorized access to app"),
			EventType:       okta.PtrString("app.generic.unauth_app_access_attempt"),
			LegacyEventType: okta.PtrString("app.generic.unauth_app_access_attempt"),
			Outcome: &okta.LogOutcome{
				Result: okta.PtrString("FAILURE"),
			},
			Published: &now,
			Request: &okta.LogRequest{
				IpChain: []okta.LogIpAddress{
					{
						GeographicalContext: &okta.LogGeographicalContext{
							City:    okta.PtrString("New York"),
							Country: okta.PtrString("US"),
							Geolocation: &okta.LogGeolocation{
								Lat: okta.PtrFloat64(40.7128),
								Lon: okta.PtrFloat64(74.0060),
							},
							PostalCode: okta.PtrString("10000"),
							State:      okta.PtrString("NY"),
						},
						Ip:      okta.PtrString("1.1.1.1"),
						Version: okta.PtrString("V4"),
					},
				},
			},
			SecurityContext: &okta.LogSecurityContext{
				AsNumber: okta.PtrInt32(1234),
				AsOrg:    okta.PtrString("some-random-org"),
				Domain:   okta.PtrString("example.com"),
				IsProxy:  &isProxy,
				Isp:      okta.PtrString("some-random-isp"),
			},
			Severity: okta.PtrString("WARN"),
			Target: []okta.LogTarget{
				{
					AlternateId: okta.PtrString("Something something"),
					DisplayName: okta.PtrString("Some display name"),
					Id:          okta.PtrString("some-random-id"),
					Type:        okta.PtrString("AppInstance"),
				},
			},
			Transaction: &okta.LogTransaction{
				Id:   okta.PtrString("some-random-id"),
				Type: okta.PtrString("WEB"),
			},
			Uuid:    okta.PtrString("some-random-uuid"),
			Version: okta.PtrString("0"),
		},
	}

	client.printEvents(events)
	// Okta log severity is mapped to logrus log level.
	assert.Contains(t, buf.String(), `"level":"warning"`)
	assert.Contains(t, buf.String(), fmt.Sprintf(`{"event":{"actor":{"alternateId":"test@example.com","displayName":"Test User","id":"some-random-id","type":"User"},"authenticationContext":{"authenticationStep":0,"externalSessionId":"some-random-id"},"client":{"device":"Computer","geographicalContext":{"city":"New York","country":"US","geolocation":{"lat":40.7128,"lon":74.006},"postalCode":"10000","state":"NY"},"id":"some-random-id","ipAddress":"1.1.1.1","userAgent":{"browser":"Chrome","os":"Mac OS X","rawUserAgent":"random-user-agent"},"zone":"null"},"debugContext":{"debugData":{"authnRequestId":"some-random-id","dtHash":"some-random-hash","redirectUri":"https://example.com/login/sso/oidc","requestId":"some-random-id","requestUri":"/oauth2/v1/authorize","threatSuspected":"false","url":"/oauth2/v1/authorize?client_id=some-random-id\u0026scope=openid+email+profile\u0026response_type=code\u0026redirect_uri=https://example.com/login/sso/oidc\u0026state=some-random-state\u0026code_challenge=some-random-code-challenge\u0026code_challenge_method=S256"}},"displayMessage":"User attempted unauthorized access to app","eventType":"app.generic.unauth_app_access_attempt","legacyEventType":"app.generic.unauth_app_access_attempt","outcome":{"result":"FAILURE"},"published":"%s","request":{"ipChain":[{"geographicalContext":{"city":"New York","country":"US","geolocation":{"lat":40.7128,"lon":74.006},"postalCode":"10000","state":"NY"},"ip":"1.1.1.1","version":"V4"}]},"securityContext":{"asNumber":1234,"asOrg":"some-random-org","domain":"example.com","isProxy":false,"isp":"some-random-isp"},"severity":"WARN","target":[{"alternateId":"Something something","displayName":"Some display name","id":"some-random-id","type":"AppInstance"}],"transaction":{"id":"some-random-id","type":"WEB"},"uuid":"some-random-uuid","version":"0"},"level":"warning","msg":"received event","time":"%s"}`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339)))
}

func TestPrintEvents_debug(t *testing.T) {
	config = &Config{
		oktaURL:          "https://example.okta.com",
		apiKey:           "your-api-key",
		logLevel:         "info",
		lookbackInterval: 24 * time.Hour,
		requestTimeout:   10 * time.Second,
		pollInterval:     5 * time.Second,
	}
	client := NewOktaClient(config)
	assert.NotNil(t, client)

	buf := bytes.NewBuffer(nil)
	setupLogger(buf, config.logLevel)

	now := time.Now()

	// Create a sample log event with severity set to DEBUG
	events := []okta.LogEvent{
		{
			Severity:  okta.PtrString("DEBUG"),
			Published: &now,
		},
	}
	client.printEvents(events)
	assert.Contains(t, buf.String(), `"severity":"DEBUG"`)
	// Okta logs with debug severity are logged as informational messages.
	// This is to prevent application-specific debug messages from being logged.
	assert.Contains(t, buf.String(), `"level":"info"`)
}

func TestPrintEvents_unknown_severity(t *testing.T) {
	config = &Config{
		oktaURL:          "https://example.okta.com",
		apiKey:           "your-api-key",
		logLevel:         "info",
		lookbackInterval: 24 * time.Hour,
		requestTimeout:   10 * time.Second,
		pollInterval:     5 * time.Second,
	}
	client := NewOktaClient(config)
	assert.NotNil(t, client)

	buf := bytes.NewBuffer(nil)
	setupLogger(buf, config.logLevel)

	now := time.Now()

	// Create a sample log event with severity set to DEBUG
	events := []okta.LogEvent{
		{
			Severity:  okta.PtrString("SOMETHING UNPARSABLE"),
			Published: &now,
		},
	}

	client.printEvents(events)
	assert.Contains(t, buf.String(), `could not parse log level`)
	assert.Contains(t, buf.String(), `"severity":"SOMETHING UNPARSABLE"`)
	// Okta logs with debug severity are logged as informational messages.
	// This is to prevent application-specific debug messages from being logged.
	assert.Contains(t, buf.String(), `"level":"info"`)
	assert.Contains(t, buf.String(), `"msg":"received event"`)
}

func TestPrintEvents_no_events(t *testing.T) {
	config = &Config{
		oktaURL:          "https://example.okta.com",
		apiKey:           "your-api-key",
		logLevel:         "info",
		lookbackInterval: 24 * time.Hour,
		requestTimeout:   10 * time.Second,
		pollInterval:     5 * time.Second,
	}
	client := NewOktaClient(config)
	assert.NotNil(t, client)

	buf := bytes.NewBuffer(nil)
	setupLogger(buf, config.logLevel)

	client.printEvents(nil)
	assert.Empty(t, buf.String())
}

func TestLogRateLimits(t *testing.T) {
	config = &Config{
		oktaURL:          "https://example.okta.com",
		apiKey:           "your-api-key",
		logLevel:         "info",
		lookbackInterval: 24 * time.Hour,
		requestTimeout:   10 * time.Second,
		pollInterval:     5 * time.Second,
	}
	client := NewOktaClient(config)
	assert.NotNil(t, client)

	response := &okta.APIResponse{
		Response: &http.Response{
			Header: map[string][]string{
				"X-Rate-Limit-Limit":     {"60"},
				"X-Rate-Limit-Remaining": {"59"},
				"X-Rate-Limit-Reset":     {"1630000000"},
			},
		},
	}

	buf := bytes.NewBuffer(nil)
	setupLogger(buf, "info")

	client.logRateLimits(response)

	assert.Empty(t, buf.String())
}

func TestLogRateLimits_remaining_less_than_2(t *testing.T) {
	config = &Config{
		oktaURL:          "https://example.okta.com",
		apiKey:           "your-api-key",
		logLevel:         "info",
		lookbackInterval: 24 * time.Hour,
		requestTimeout:   10 * time.Second,
		pollInterval:     5 * time.Second,
	}
	client := NewOktaClient(config)
	assert.NotNil(t, client)

	response := &okta.APIResponse{
		Response: &http.Response{
			Header: map[string][]string{
				"X-Rate-Limit-Limit":     {"60"},
				"X-Rate-Limit-Remaining": {"1"},
				"X-Rate-Limit-Reset":     {"1630000000"},
			},
		},
	}

	buf := bytes.NewBuffer(nil)
	setupLogger(buf, "info")

	client.logRateLimits(response)

	assert.Contains(t, buf.String(), `"level":"warning"`)
	assert.Contains(t, buf.String(), `"limit":60`)
	assert.Contains(t, buf.String(), `"remaining":1`)
	assert.Contains(t, buf.String(), `"reset":"1630000000"`)
}

func TestLogRateLimits_missing_rate_limit(t *testing.T) {
	config = &Config{
		oktaURL:          "https://example.okta.com",
		apiKey:           "your-api-key",
		logLevel:         "info",
		lookbackInterval: 24 * time.Hour,
		requestTimeout:   10 * time.Second,
		pollInterval:     5 * time.Second,
	}
	client := NewOktaClient(config)
	assert.NotNil(t, client)

	response := &okta.APIResponse{
		Response: &http.Response{},
	}

	buf := bytes.NewBuffer(nil)
	setupLogger(buf, "info")

	client.logRateLimits(response)

	assert.Contains(t, buf.String(), `"level":"error"`)
	assert.Contains(t, buf.String(), `"error":"strconv.Atoi: parsing \"\": invalid syntax"`)
	assert.Contains(t, buf.String(), `"msg":"could not parse rate limit"`)
}

func TestLogRateLimits_missing_remaining_rate_limit(t *testing.T) {
	config = &Config{
		oktaURL:          "https://example.okta.com",
		apiKey:           "your-api-key",
		logLevel:         "info",
		lookbackInterval: 24 * time.Hour,
		requestTimeout:   10 * time.Second,
		pollInterval:     5 * time.Second,
	}
	client := NewOktaClient(config)
	assert.NotNil(t, client)

	response := &okta.APIResponse{
		Response: &http.Response{
			Header: map[string][]string{
				"X-Rate-Limit-Limit": {"60"},
			},
		},
	}

	buf := bytes.NewBuffer(nil)
	setupLogger(buf, "info")

	client.logRateLimits(response)

	assert.Contains(t, buf.String(), `"level":"error"`)
	assert.Contains(t, buf.String(), `"error":"strconv.Atoi: parsing \"\": invalid syntax"`)
	assert.Contains(t, buf.String(), `"msg":"could not parse remaining rate limit"`)
}

func TestLogRateLimits_missing_reset_rate_limit(t *testing.T) {
	config = &Config{
		oktaURL:          "https://example.okta.com",
		apiKey:           "your-api-key",
		logLevel:         "info",
		lookbackInterval: 24 * time.Hour,
		requestTimeout:   10 * time.Second,
		pollInterval:     5 * time.Second,
	}
	client := NewOktaClient(config)
	assert.NotNil(t, client)

	response := &okta.APIResponse{
		Response: &http.Response{
			Header: map[string][]string{
				"X-Rate-Limit-Limit":     {"60"},
				"X-Rate-Limit-Remaining": {"1"},
			},
		},
	}

	buf := bytes.NewBuffer(nil)
	setupLogger(buf, "info")

	client.logRateLimits(response)

	assert.Contains(t, buf.String(), `"level":"warning"`)
	assert.Contains(t, buf.String(), `"limit":60`)
	assert.Contains(t, buf.String(), `"remaining":1`)
	assert.Contains(t, buf.String(), `"reset":""`) // reset is empty when not present
}

func TestPollSystemLogs_invalid_token(t *testing.T) {
	config = &Config{
		oktaURL:          "https://example.okta.com",
		apiKey:           "your-api-key",
		logLevel:         "info",
		lookbackInterval: 24 * time.Hour,
		requestTimeout:   10 * time.Second,
		pollInterval:     5 * time.Second,
	}
	client := NewOktaClient(config)
	assert.NotNil(t, client)

	buf := bytes.NewBuffer(nil)
	setupLogger(buf, config.logLevel)

	err := client.PollSystemLogs()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unauthorized")
}

func TestPollSystemLogs_mock(t *testing.T) {
	config := &Config{
		oktaURL:          "https://example.okta.com",
		apiKey:           "your-api-key",
		logLevel:         "info",
		lookbackInterval: 24 * time.Hour,
		requestTimeout:   10 * time.Second,
		pollInterval:     5 * time.Second,
	}
	client := NewOktaClient(config)
	assert.NotNil(t, client)

	buf := bytes.NewBuffer(nil)
	setupLogger(buf, config.logLevel)

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder(
		"GET",
		"https://example.okta.com/api/v1/logs",
		httpmock.NewJsonResponderOrPanic(200, httpmock.File(`testdata/response.json`)),
	)

	// Replace the underlying HTTP client with httpmock's
	client.client.GetConfig().HTTPClient = &http.Client{Transport: httpmock.DefaultTransport}

	err := client.PollSystemLogs()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "poll ended")
}

func TestSanitizeUserIdentity(t *testing.T) {
	tests := []struct {
		name     string
		input    *okta.LogEvent
		expected *okta.LogEvent
	}{
		{
			name: "Actor is not User type",
			input: &okta.LogEvent{
				Actor: &okta.LogActor{Type: okta.PtrString("Service"), DisplayName: okta.PtrString("actor1"), AlternateId: okta.PtrString("alt1")},
				Target: []okta.LogTarget{
					{Type: okta.PtrString("User"), DisplayName: okta.PtrString("target1"), AlternateId: okta.PtrString("alt1")},
				},
			},
			expected: &okta.LogEvent{
				Actor: &okta.LogActor{Type: okta.PtrString("Service"), DisplayName: okta.PtrString("actor1"), AlternateId: okta.PtrString("alt1")},
				Target: []okta.LogTarget{
					{Type: okta.PtrString("User"), DisplayName: okta.PtrString("t...1"), AlternateId: okta.PtrString("a...1")},
				},
			},
		},
		{
			name: "Actor is User type",
			input: &okta.LogEvent{
				Actor: &okta.LogActor{Type: okta.PtrString("User"), DisplayName: okta.PtrString("actor1"), AlternateId: okta.PtrString("alt1")},
				Target: []okta.LogTarget{
					{Type: okta.PtrString("User"), DisplayName: okta.PtrString("target1"), AlternateId: okta.PtrString("alt1")},
				},
			},
			expected: &okta.LogEvent{
				Actor: &okta.LogActor{Type: okta.PtrString("User"), DisplayName: okta.PtrString("a...1"), AlternateId: okta.PtrString("a...1")},
				Target: []okta.LogTarget{
					{Type: okta.PtrString("User"), DisplayName: okta.PtrString("t...1"), AlternateId: okta.PtrString("a...1")},
				},
			},
		},
		{
			name: "Target is not User type",
			input: &okta.LogEvent{
				Actor: &okta.LogActor{Type: okta.PtrString("User"), DisplayName: okta.PtrString("actor1"), AlternateId: okta.PtrString("alt1")},
				Target: []okta.LogTarget{
					{Type: okta.PtrString("Service"), DisplayName: okta.PtrString("target1"), AlternateId: okta.PtrString("alt1")},
				},
			},
			expected: &okta.LogEvent{
				Actor: &okta.LogActor{Type: okta.PtrString("User"), DisplayName: okta.PtrString("a...1"), AlternateId: okta.PtrString("a...1")},
				Target: []okta.LogTarget{
					{Type: okta.PtrString("Service"), DisplayName: okta.PtrString("target1"), AlternateId: okta.PtrString("alt1")},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sanitizeUserIdentity(tt.input)
			assert.Equal(t, tt.expected, tt.input)
		})
	}
}
