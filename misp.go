package misp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

// Client ... XXX
type Client struct {
	BaseURL *url.URL
	APIKey  string
}

// Sighting ... XXX
type Sighting struct {
	ID        string   `json:"id,omitempty"`
	UUID      string   `json:"uuid,omitempty"`
	Value     string   `json:"value,omitempty"`
	Values    []string `json:"values,omitempty"`
	Timestamp int      `json:"timestamp,omitempty"`
}

// Request ... XXX
type Request struct {
	Request interface{} `json:"request"`
}

// SampleFile ... XXX
type SampleFile struct {
	Filename string `json:"filename,omitempty"`
	Data     string `json:"data,omitempty"`
}

// SampleUpload ... XXX
type SampleUpload struct {
	Files        []SampleFile `json:"files,omitempty"`
	Distribution int          `json:"distribution,omitempty"`
	Comment      string       `json:"comment,omitempty"` // comment field of any attribute created
	EventID      int          `json:"event_id,omitempty"`
	ToIDS        bool         `json:"to_ids,omitempty"`
	Category     string       `json:"category,omitempty"`
	Info         string       `json:"info,omitempty"` // event info field if no event ID supplied
}

// XResponse ... XXX
type XResponse struct {
	Name    string `json:"name,omitempty"`
	Message string `json:"message,omitempty"`
	URL     string `json:"url,omitempty"`
	Errors  string `json:"errors,omitempty"`
	ID      int    `json:"id,omitempty"`
}

// Response is the outer layer of each MISP response
type Response struct {
	Response InnerResponse `json:"response"`
}

// InnerResponse ...
type InnerResponse struct {
	Attribute []Attribute `json:"Attribute,omitempty"`
}

// Attribute ...
type Attribute struct {
	Comment            string `json:"comment,omitempty"`
	ID                 string `json:"id,omitempty"`
	EventID            string `json:"event_id,omitempty"`
	Distribution       string `json:"distribution,omitempty"`
	ObjectID           string `json:"object_id,omitempty"`
	ObjectRelation     string `json:"object_relation,omitempty"`
	DisableCorrelation bool   `json:"disable_correlation,omitempty"`
	Deleted            bool   `json:"deleted,omitempty"`
	Filename           string `json:"filename,omitempty"`
	Type               string `json:"type,omitempty"`
	Timestamp          string `json:"timestamp,omitempty"`
	Value              string `json:"value,omitempty"`
	SharingGroupID     string `json:"sharing_group_id,omitempty"`
	Category           string `json:"category,omitempty"`
	UUID               string `json:"uuid,omitempty"`
	ToIDS              bool   `json:"to_ids,omitempty"`
}

// AttributeQuery ...
type AttributeQuery struct {
	// Search for the given value in the attributes' value field.
	Value string `json:"value,omitempty"`

	// The attribute type, any valid MISP attribute type is accepted.
	Type string `json:"type,omitempty"`

	// The attribute category, any valid MISP attribute category is accepted.
	Category string `json:"category,omitempty"`

	// Search by the creator organisation by supplying the organisation idenfitier.
	Org string `json:"org,omitempty"`

	// To include a tag in the results just write its names into this
	// parameter. To exclude a tag prepend it with a '!'. You can also chain
	// several tag commands together with the '&&' operator. Please be aware
	// the colons (:) cannot be used in the tag search. Use semicolons instead
	// (the search will automatically search for colons instead).
	Tags string `json:"tags,omitempty"`

	// Events with the date set to a date after the one specified in the from
	// field (format: 2015-02-15). This filter will use the date of the event.
	From string `json:"from,omitempty"`

	// Events with the date set to a date before the one specified in the to
	// field (format: 2015-02-15). This filter will use the date of the event.
	To string `json:"to,omitempty"`

	// Events published within the last x amount of time, where x can be
	// defined in days, hours, minutes (for example 5d or 12h or 30m). This
	// filter will use the published timestamp of the event.
	Last string `json:"last,omitempty"`

	// The events that should be included / excluded from the search
	EventID string `json:"eventid,omitempty"`

	// Include the attachments/encrypted samples in the export
	WithAttachment string `json:"withAttachments,omitempty"`

	// Only fetch the event metadata (event data, tags, relations) and skip the attributes
	MetaData string `json:"metadata,omitempty"`

	// The returned events must include an attribute with the given UUID, or
	// alternatively the event's UUID must match the value(s) passed.
	UUID string `json:"uuid,omitempty"`
}

// Search ... XXX
func (client *Client) Search() {
	// client.Do("/")

}

// AddSighting ... XXX
func (client *Client) AddSighting(s *Sighting) (*Response, error) {
	httpResp, err := client.Post("/sightings/add/", Request{Request: s})
	if err != nil {
		return nil, err
	}

	var response Response
	decoder := json.NewDecoder(httpResp.Body)
	if err = decoder.Decode(&response); err != nil {
		return nil, err
	}

	return &response, nil
}

// UploadResponse ... XXX
type UploadResponse struct {
	ID string
}

// UploadSample ... XXX
func (client *Client) UploadSample(sample *SampleUpload) (*UploadResponse, error) {
	req := &Request{Request: sample}

	httpResp, err := client.Post("/events/upload_sample/", req)
	if err != nil {
		return nil, err
	}

	var response UploadResponse
	decoder := json.NewDecoder(httpResp.Body)
	if err = decoder.Decode(&response); err != nil {
		return nil, err
	}

	return &response, nil
}

// Get is a wrapper to Do()
func (client *Client) Get(path string, req interface{}) (*http.Response, error) {
	return client.Do("GET", path, req)
}

// Post is a wrapper to Do()
func (client *Client) Post(path string, req interface{}) (*http.Response, error) {
	return client.Do("POST", path, req)
}

// SearchAttribute ...
func (client *Client) SearchAttribute(q *AttributeQuery) ([]Attribute, error) {
	httpResp, err := client.Post("/attributes/restSearch/json/", Request{Request: q})
	if err != nil {
		return nil, err
	}

	var response Response
	decoder := json.NewDecoder(httpResp.Body)
	if err = decoder.Decode(&response); err != nil {
		return nil, err
	}

	return response.Response.Attribute, nil
}

// Do set the HTTP headers, encode the data in the JSON format and send it to the
// server.
// It checks the HTTP response by looking at the status code and decodes the JSON structure
// to a Response structure.
func (client *Client) Do(method, path string, req interface{}) (*http.Response, error) {
	jsonBuf, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq := &http.Request{}
	httpReq.Method = method
	httpReq.Body = ioutil.NopCloser(bytes.NewReader(jsonBuf))
	httpReq.URL = client.BaseURL
	httpReq.URL.Path = path

	httpReq.Header = make(http.Header)
	httpReq.Header.Set("Authorization", client.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	httpClient := http.Client{}
	resp, err := httpClient.Do(httpReq)
	if resp.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("MISP server replied status=%d", resp.StatusCode)
	}

	return resp, nil
}
