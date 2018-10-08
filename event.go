package misp

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Event represents a MISP event
type Event struct {
	client    *Client
	ID        string      `json:"id"`
	UUID      string      `json:"uuid"`
	Attribute []Attribute `json:"Attribute"`
}

// DownloadResponse represents the response of a DownloadRequest
type DownloadResponse struct {
	Result []DownloadResponseFile `json:"result"`
}

// DownloadResponseFile represents a malware sample
type DownloadResponseFile struct {
	MD5         string `json:"md5"`
	Base64      string `json:"base64"`
	Filename    string `json:"filename"`
	AttributeID string `json:"attribute_id"`
	EventID     string `json:"event_id"`
	EventInfo   string `json:"event_info"`
}

// DownloadSample downloads a malware sample to a given file
func (event *Event) DownloadSample(hash string, filename string) error {
	type requestAllSamples struct {
		Hash       string `json:"hash"`
		EventID    int    `json:"eventID"`
		AllSamples int    `json:"allSamples"`
	}

	type requestNotAllSamples struct {
		Hash    string `json:"hash"`
		EventID int    `json:"eventID"`
	}

	var actualRequest interface{}
	eventID, _ := strconv.Atoi(event.ID)
	if hash == "" {
		actualRequest = requestAllSamples{
			Hash:       hash,
			EventID:    eventID,
			AllSamples: 1,
		}
	} else {
		actualRequest = requestNotAllSamples{
			Hash:    hash,
			EventID: eventID,
		}
	}

	resp, err := event.client.Get("/attributes/downloadSample/", Request{
		Request: actualRequest,
	})

	// Parse response
	var downloadResponse DownloadResponse
	jsonDecoder := json.NewDecoder(resp.Body)
	if err = jsonDecoder.Decode(&downloadResponse); err != nil {
		return fmt.Errorf("Error decoding response: %s", err)
	}

	if len(downloadResponse.Result) == 0 {
		return fmt.Errorf("No results")
	}

	// Download attachment
	// TODO: it's cool to use DownloadAttachment because DRY, but we end up downloading the file twice...
	attrID, _ := strconv.ParseInt(downloadResponse.Result[0].AttributeID, 10, 32)
	return event.client.DownloadAttachment(int(attrID), filename)
}

// AddTag adds a tag to a given event
func (event *Event) AddTag(tagName string) error {
	type tagRequest struct {
		UUID string `json:"uuid"`
		Tag  string `json:"tag"`
	}

	req := tagRequest{
		UUID: event.UUID,
		Tag:  tagName,
	}

	_, err := event.client.Post("/tags/attachTagToObject", req)
	if err != nil {
		return err
	}

	return nil
}
