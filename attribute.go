package misp

// Attribute represents a MISP attribute
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

// AddTag adds a tag to this attribute
func (a *Attribute) AddTag(client Client, tagName string) error {
	type tagRequest struct {
		UUID string `json:"uuid"`
		Tag  string `json:"tag"`
	}

	req := tagRequest{
		UUID: a.UUID,
		Tag:  tagName,
	}

	_, err := client.Post("/tags/attachTagToObject", req)
	if err != nil {
		return err
	}

	return nil
}
