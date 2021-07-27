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
	Tags      []Tag       `json:"Tag"`
	Objects   []Object    `json:"Object"`
	Info      string      `json:"Info"`
	Date      string      `json:"Date"`
	Org       Org         `json::Org`
	Orgc      Org         `json::Orgc`
}

// Tag represents an event tag
type Tag struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Colour     string `json:"colour"`
	Exportable bool   `json:"exportable"`
}

// Org represents an event tag
type Org struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

// Object is a MISP object
type Object struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	MetaCategory string      `json:"meta-category"`
	Description  string      `json:"description"`
	EventID      string      `json:"event_id"`
	UUID         string      `json:"uuid"`
	Timestamp    string      `json:"timestamp"`
	Attributes   []Attribute `json:"Attribute"`
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

func (event *Event) downloadSampleRequest(request interface{}) (*DownloadResponse, error) {
	resp, err := event.client.Get("/attributes/downloadSample/", Request{
		Request: request,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse response
	var downloadResponse DownloadResponse
	jsonDecoder := json.NewDecoder(resp.Body)
	if err = jsonDecoder.Decode(&downloadResponse); err != nil {
		return nil, fmt.Errorf("Error decoding response: %s", err)
	}

	if len(downloadResponse.Result) == 0 {
		return nil, fmt.Errorf("No results")
	}

	return &downloadResponse, nil
}

// DownloadSampleByHash downloads a malware sample identified by a hash to a given file.
func (event *Event) DownloadSampleByHash(hash string, filename string) error {
	type requestNotAllSamples struct {
		Hash    string `json:"hash"`
		EventID int    `json:"eventID"`
	}

	eventID, _ := strconv.Atoi(event.ID)
	response, err := event.downloadSampleRequest(requestNotAllSamples{
		Hash:    hash,
		EventID: eventID,
	})
	if err != nil {
		return err
	}

	// Download attachment
	// TODO: it's cool to use DownloadAttachment because DRY, but we end up downloading the file twice...
	attrID, _ := strconv.ParseInt(response.Result[0].AttributeID, 10, 32)
	return event.client.DownloadAttachment(int(attrID), filename)
}

// DownloadNthSample downloads the "n"th sample from this event to the given filename. Starts at 0
func (event *Event) DownloadNthSample(n int, filename string) error {
	type requestAllSamples struct {
		EventID    int `json:"eventID"`
		AllSamples int `json:"allSamples"`
	}

	eventID, _ := strconv.ParseInt(event.ID, 10, 32)

	response, err := event.downloadSampleRequest(requestAllSamples{
		EventID:    int(eventID),
		AllSamples: 1,
	})
	if err != nil {
		return err
	}

	if len(response.Result) <= n {
		return fmt.Errorf("Too few results: %d", len(response.Result))
	}

	attrID, _ := strconv.ParseInt(response.Result[n].AttributeID, 10, 32)
	return event.client.DownloadAttachment(int(attrID), filename)
}

// DownloadAllSamples downloads all samples from the event. filenamePattern should have a %d that will be replaced by the sample index
func (event *Event) DownloadAllSamples(filenamePattern string) error {
	type requestAllSamples struct {
		EventID    int `json:"eventID"`
		AllSamples int `json:"allSamples"`
	}

	eventID, _ := strconv.ParseInt(event.ID, 10, 32)

	response, err := event.downloadSampleRequest(requestAllSamples{
		EventID:    int(eventID),
		AllSamples: 1,
	})
	if err != nil {
		return err
	}

	for n, result := range response.Result {
		attrID, _ := strconv.ParseInt(result.AttributeID, 10, 32)
		err = event.client.DownloadAttachment(int(attrID), fmt.Sprintf(filenamePattern, n))
		if err != nil {
			return err
		}
	}

	return nil
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
