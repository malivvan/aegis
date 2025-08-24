package kdbx

import (
	"encoding/xml"

	w "github.com/malivvan/aegis/kdbx/wrappers"
)

// DeletedObjectData is the structure for a deleted object
type DeletedObjectData struct {
	XMLName      xml.Name       `xml:"DeletedObject"`
	UUID         UUID           `xml:"UUID"`
	DeletionTime *w.TimeWrapper `xml:"DeletionTime"`
}

func (d *DeletedObjectData) setKdbxFormatVersion(version formatVersion) {
	d.DeletionTime.Formatted = !isKdbx4(version)
}
