package httptime

import (
	"encoding/json"
	"time"
)

var bogota *time.Location

func init() {
	var err error
	bogota, err = time.LoadLocation("America/Bogota")
	if err != nil {
		bogota = time.FixedZone("BOT", -5*3600)
	}
}

// FormatRFC3339 formatea el instante en America/Bogota (RFC3339) para respuestas HTTP.
func FormatRFC3339(t time.Time) string {
	if t.IsZero() {
		return t.UTC().Format(time.RFC3339)
	}
	return t.In(bogota).Format(time.RFC3339)
}

// JSONTime serializa time.Time como cadena RFC3339 en hora de Bogotá.
type JSONTime time.Time

func (t JSONTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(FormatRFC3339(time.Time(t)))
}

// JSONPtr serializa *time.Time en hora de Bogotá o null.
type JSONPtr struct {
	*time.Time
}

func (p JSONPtr) MarshalJSON() ([]byte, error) {
	if p.Time == nil {
		return []byte("null"), nil
	}
	return JSONTime(*p.Time).MarshalJSON()
}
