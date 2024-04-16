package sms_provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
)

const (
	defaultPostackApiBase = "https://api.postack.dev"
)

type PostackProvider struct {
	Config  *conf.PostackProviderConfiguration
	APIPath string
}

type PostackResponse struct {
	ID 				string `json:"id"`
	Status    string `json:"status"`
}

type PostackErrResponse struct {
	Code        string    `json:"code"`
	Message 		string		`json:"message"`
}

func (t PostackErrResponse) Error() string {
	return t.Message
}

// Creates a SmsProvider with the Postack Config
func NewPostackProvider(config conf.PostackProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	apiPath := defaultPostackApiBase + "/v1/verifications/sms"
	return &PostackProvider{
		Config:  &config,
		APIPath: apiPath,
	}, nil
}

func (t *PostackProvider) SendMessage(phone, message, channel, otp string) (string, error) {
	switch channel {
	case SMSProvider:
		return t.SendSms(phone, otp)
	default:
		return "", fmt.Errorf("channel type %q is not supported for Postack", channel)
	}
}

// Send an SMS containing the OTP with Postack's API
func (t *PostackProvider) SendSms(phone, otp string) (string, error) {
	body := url.Values{
		"verification[to]": {"+" + phone},
		"verification[verification_profile_id]": {t.Config.ProfileId},
		"verification[code]": {otp},
	}

	client := &http.Client{Timeout: defaultTimeout}
	r, err := http.NewRequest("POST", t.APIPath, strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Authorization", "Bearer "+t.Config.ApiKey)
	res, err := client.Do(r)
	if err != nil {
		return "", err
	}

	if res.StatusCode == http.StatusBadRequest || res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusUnprocessableEntity {
		resp := &PostackErrResponse{}
		if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
			return "", err
		}
		return "", resp
	}
	defer utilities.SafeClose(res.Body)

	// validate sms status
	resp := &PostackResponse{}
	derr := json.NewDecoder(res.Body).Decode(resp)
	if derr != nil {
		return "", derr
	}

	return resp.ID, nil
}
