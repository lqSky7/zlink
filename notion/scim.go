package notion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const defaultSCIMBase = "https://api.notion.com/scim/v2"

type scimClient struct {
	httpClient *http.Client
	baseURL    string
	token      string
}

func newSCIMClient(token string, httpClient *http.Client, baseURL string) *scimClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if baseURL == "" {
		baseURL = defaultSCIMBase
	}
	return &scimClient{
		httpClient: httpClient,
		baseURL:    baseURL,
		token:      token,
	}
}

type scimUser struct {
	ID       string `json:"id"`
	UserName string `json:"userName"`
	Active   bool   `json:"active"`
}

type scimListResponse struct {
	Resources    []scimUser `json:"Resources"`
	TotalResults int        `json:"totalResults"`
}

type scimGroupPatch struct {
	Schemas    []string      `json:"schemas"`
	Operations []scimPatchOp `json:"Operations"`
}

type scimPatchOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

func (s *scimClient) FindUserByEmail(ctx context.Context, email string) (*scimUser, error) {
	url := fmt.Sprintf("%s/Users?filter=email eq \"%s\"", s.baseURL, email)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	s.setHeaders(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SCIM GET /Users returned %d", resp.StatusCode)
	}

	var result scimListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if len(result.Resources) == 0 {
		return nil, nil
	}
	return &result.Resources[0], nil
}

func (s *scimClient) CreateUser(ctx context.Context, email, givenName, familyName string) (*scimUser, error) {
	body := map[string]interface{}{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": email,
		"name": map[string]string{
			"givenName":  givenName,
			"familyName": familyName,
		},
		"emails": []map[string]interface{}{
			{"value": email, "primary": true},
		},
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/Users", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	s.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("SCIM POST /Users returned %d: %s", resp.StatusCode, string(respBody))
	}

	var user scimUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *scimClient) DeleteUser(ctx context.Context, userID string) error {
	url := fmt.Sprintf("%s/Users/%s", s.baseURL, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	s.setHeaders(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SCIM DELETE /Users/%s returned %d", userID, resp.StatusCode)
	}
	return nil
}

func (s *scimClient) AddUserToGroup(ctx context.Context, groupID, userID string) error {
	patch := scimGroupPatch{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []scimPatchOp{
			{
				Op:   "add",
				Path: "members",
				Value: []map[string]string{
					{"value": userID},
				},
			},
		},
	}
	return s.patchGroup(ctx, groupID, patch)
}

func (s *scimClient) RemoveUserFromGroup(ctx context.Context, groupID, userID string) error {
	patch := scimGroupPatch{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []scimPatchOp{
			{
				Op:   "remove",
				Path: fmt.Sprintf("members[value eq \"%s\"]", userID),
			},
		},
	}
	return s.patchGroup(ctx, groupID, patch)
}

func (s *scimClient) patchGroup(ctx context.Context, groupID string, patch scimGroupPatch) error {
	data, err := json.Marshal(patch)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/Groups/%s", s.baseURL, groupID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	s.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("SCIM PATCH /Groups/%s returned %d: %s", groupID, resp.StatusCode, string(respBody))
	}
	return nil
}

func (s *scimClient) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Accept", "application/json")
}
