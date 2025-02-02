package misp

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

// Interface that list all available interface
type Misp interface {
	Search()
	GetBaseURL()(*url.URL)
	GetEventByID(eventID string) (*Event, error)
	GetAttributeByID(attrID string) (*Attribute, error)
	PublishEvent(eventID string, email bool) (*Response, error)
	AddSighting(s *Sighting) (*Response, error)
	UploadSample(sample *SampleUpload) (*UploadResponse, error)
	DownloadAttachment(attributeID int, filename string) error
	Get(path string, req interface{}) (*http.Response, error)
	Post(path string, req interface{}) (*http.Response, error)
	SearchAttribute(q *AttributeQuery) ([]Attribute, error)
	Do(method, path string, req interface{}) (*http.Response, error)
}

// Client ... XXX
type Client struct {
	Misp
	BaseURL           *url.URL
	APIKey            string
	IgnoreInsecureSSL bool
	Timeout           time.Duration // Timeout specifies how long to wait for a response from MISP. Zero means no timeout
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
	Distribution string       `json:"distribution,omitempty"`
	Comment      string       `json:"comment,omitempty"` // comment field of any attribute created
	EventID      string       `json:"event_id,omitempty"`
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
}

type searchOuterResponse struct {
	// Response can be an empty array or an object
	Response json.RawMessage `json:"response"`
}

type searchInnerResponse struct {
	Attribute []Attribute `json:"Attribute,omitempty"`
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

func (client *Client)GetBaseURL()(*url.URL) {
	return client.BaseURL
}

// GetEventByID fetches the Event which has the given eventID
func (client *Client) GetEventByID(eventID string) (*Event, error) {
	type eventResponseType struct {
		Event Event `json:"Event"`
	}

	path := fmt.Sprintf("/events/%s", eventID)

	resp, err := client.Get(path, nil)
	if err != nil {
		return nil, err
	}

	var eventResult eventResponseType
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&eventResult); err != nil {
		return nil, fmt.Errorf("Could not unmarshal event: %s", err)
	}

	result := &eventResult.Event
	result.client = client

	return result, nil
}

// GetAttributeByID fetches an attribute by its ID or UUID
func (client *Client) GetAttributeByID(attrID string) (*Attribute, error) {
	type attrResponseType struct {
		Attribute Attribute `json:"Attribute"`
	}

	path := fmt.Sprintf("/attributes/%s", attrID)

	resp, err := client.Get(path, nil)
	if err != nil {
		return nil, err
	}

	var attrResult attrResponseType
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&attrResult); err != nil {
		return nil, fmt.Errorf("Could not unmarshal attribute: %s", err)
	}

	return &attrResult.Attribute, nil
}

// PublishEvent ... XXX
func (client *Client) PublishEvent(eventID string, email bool) (*Response, error) {
	var path string
	if email {
		path = "/events/alert/%s"
	} else {
		path = "/events/publish/%s"
	}

	path = fmt.Sprintf(path, eventID)

	_, err := client.Post(path, nil)

	return nil, err
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
	ID      int      `json:"nononoid"`
	RawID   string   `json:"id"`
	URL     string   `json:"url"`
	Message string   `json:"message"`
	Name    string   `json:"name"`
	Errors  []string `json:"errors"`
}

// UploadSample ... XXX
func (client *Client) UploadSample(sample *SampleUpload) (*UploadResponse, error) {
	req := &Request{Request: sample}

	url := fmt.Sprintf("/events/upload_sample/%s", sample.EventID)
	httpResp, err := client.Post(url, req)
	if err != nil {
		return nil, err
	}

	var resp UploadResponse
	decoder := json.NewDecoder(httpResp.Body)
	if err = decoder.Decode(&resp); err != nil {
		return nil, fmt.Errorf("Could not unmarshal response: %s", err)
	}

	if len(resp.Errors) > 0 {
		return nil, fmt.Errorf("MISP returned an error: %v", resp)
	}

	id, err := strconv.ParseInt(resp.RawID, 10, 32)
	if err != nil {
		return nil, err
	}
	resp.ID = int(id)

	return &resp, nil
}

// DownloadAttachment downloads an attachment or malware sample to the given file
func (client *Client) DownloadAttachment(attributeID int, filename string) error {
	path := fmt.Sprintf("/attributes/downloadAttachment/download/%d", attributeID)

	defaultTransport := http.DefaultTransport.(*http.Transport)

	// Create new Transport that ignores self-signed SSL
	tr := &http.Transport{
		Proxy:                 defaultTransport.Proxy,
		DialContext:           defaultTransport.DialContext,
		MaxIdleConns:          defaultTransport.MaxIdleConns,
		IdleConnTimeout:       defaultTransport.IdleConnTimeout,
		ExpectContinueTimeout: defaultTransport.ExpectContinueTimeout,
		TLSHandshakeTimeout:   defaultTransport.TLSHandshakeTimeout,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: false},
	}

	if client.IgnoreInsecureSSL {
		tr.TLSClientConfig.InsecureSkipVerify = true
	}

	httpReq := &http.Request{}
	httpReq.Method = "GET"
	httpReq.URL = client.BaseURL
	httpReq.URL.Path = path

	httpReq.Header = make(http.Header)
	httpReq.Header.Set("Authorization", client.APIKey)

	httpClient := http.Client{
		Transport: tr,
		Timeout:   client.Timeout,
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("Error downloading attachment: %s", err)
	}
	defer resp.Body.Close()

	outFile, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return fmt.Errorf("Error opening %s: %s", filename, err)
	}

	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return fmt.Errorf("Error writing to %s: %s", filename, err)
	}

	return nil
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

	var outer searchOuterResponse
	// tee := io.TeeReader(httpResp.Body, os.Stdout)
	// decoder := json.NewDecoder(tee)
	decoder := json.NewDecoder(httpResp.Body)
	if err = decoder.Decode(&outer); err != nil {
		return nil, fmt.Errorf("Could not unmarshal response: %s", err)
	}

	var inner searchInnerResponse
	if err := json.Unmarshal(outer.Response, &inner); err != nil {
		var empty []string
		if err := json.Unmarshal(outer.Response, &empty); err != nil {
			return nil, fmt.Errorf("Inner structure has unknown format: %s", outer.Response)
		}
		return []Attribute{}, nil
	}

	return inner.Attribute, nil
}

// Do set the HTTP headers, encode the data in the JSON format and send it to the
// server.
// It checks the HTTP response by looking at the status code and decodes the JSON structure
// to a Response structure.
func (client *Client) Do(method, path string, req interface{}) (*http.Response, error) {
	httpReq := &http.Request{}

	defaultTransport := http.DefaultTransport.(*http.Transport)

	// Create new Transport that ignores self-signed SSL
	tr := &http.Transport{
		Proxy:                 defaultTransport.Proxy,
		DialContext:           defaultTransport.DialContext,
		MaxIdleConns:          defaultTransport.MaxIdleConns,
		IdleConnTimeout:       defaultTransport.IdleConnTimeout,
		ExpectContinueTimeout: defaultTransport.ExpectContinueTimeout,
		TLSHandshakeTimeout:   defaultTransport.TLSHandshakeTimeout,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: false},
	}

	if client.IgnoreInsecureSSL {
		tr.TLSClientConfig.InsecureSkipVerify = true
	}

	if req != nil {
		jsonBuf, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		httpReq.Body = ioutil.NopCloser(bytes.NewReader(jsonBuf))
	}

	httpReq.Method = method
	httpReq.URL = client.BaseURL
	httpReq.URL.Path = path

	httpReq.Header = make(http.Header)
	httpReq.Header.Set("Authorization", client.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	httpClient := http.Client{
		Transport: tr,
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("MISP server replied status=%d", resp.StatusCode)
	}

	return resp, nil
}
