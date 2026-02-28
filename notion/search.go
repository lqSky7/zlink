package notion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const notionAPIBase = "https://api.notion.com/v1"

func doNotionSearch(ctx context.Context, client *http.Client, token string, body map[string]interface{}) (*searchResult, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, notionAPIBase+"/search", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Notion-Version", "2022-06-28")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Notion search returned %d", resp.StatusCode)
	}

	var raw struct {
		Results []struct {
			ID         string `json:"id"`
			Object     string `json:"object"`
			Properties map[string]struct {
				Title []struct {
					PlainText string `json:"plain_text"`
				} `json:"title"`
			} `json:"properties"`
		} `json:"results"`
		HasMore    bool   `json:"has_more"`
		NextCursor string `json:"next_cursor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	result := &searchResult{
		HasMore:    raw.HasMore,
		NextCursor: raw.NextCursor,
	}
	for _, r := range raw.Results {
		title := ""
		for _, prop := range r.Properties {
			if len(prop.Title) > 0 {
				title = prop.Title[0].PlainText
				break
			}
		}
		result.Results = append(result.Results, searchObject{
			ID:    r.ID,
			Type:  r.Object,
			Title: title,
		})
	}
	return result, nil
}
