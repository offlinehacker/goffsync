package x

import (
	"encoding/json"
	"fmt"
	"math"
	"time"
)

func PatchJson[JV string | []byte](rawjson JV, key string, value any) (JV, error) {
	var err error

	var jsonpayload map[string]any
	err = json.Unmarshal([]byte(rawjson), &jsonpayload)
	if err != nil {
		return *new(JV), fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	jsonpayload[key] = value

	newjson, err := json.Marshal(jsonpayload)
	if err != nil {
		return *new(JV), fmt.Errorf("failed to re-marshal payload: %w", err)
	}

	return JV(newjson), nil
}

type UnixTime time.Time

func (t UnixTime) Time() time.Time {
	return time.Time(t)
}

// MarshalJSON implements the json.Marshaler interface
func (t UnixTime) MarshalJSON() ([]byte, error) {
	milliseconds := time.Time(t).UnixNano() / int64(time.Millisecond)
	return json.Marshal(milliseconds)
}

func (t *UnixTime) UnmarshalJSON(bytes []byte) error {
	var msec int64
	err := json.Unmarshal(bytes, &msec)
	if err != nil {
		return err
	}

	*t = UnixTime(time.UnixMilli(msec))
	return nil
}

type IntSecondsDuration time.Duration

// MarshalJSON implements the json.Marshaler interface.
// It converts the IntSecondsTime to seconds and marshals it as a JSON number.
func (t IntSecondsDuration) MarshalJSON() ([]byte, error) {
	seconds := int64(time.Duration(t).Seconds())
	return json.Marshal(seconds)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// It unmarshals a JSON number representing seconds and converts it to IntSecondsTime.
func (t *IntSecondsDuration) UnmarshalJSON(data []byte) error {
	var seconds int64
	if err := json.Unmarshal(data, &seconds); err != nil {
		return err
	}
	*t = IntSecondsDuration(time.Duration(seconds) * time.Second)
	return nil
}

// UnixFloatTime is a custom Time type that supports json marshal/unmarshal
// from float based unix time (in seconds)
type UnixFloatTime time.Time

func (t UnixFloatTime) Time() time.Time {
	return time.Time(t)
}

func (t UnixFloatTime) MarshalJSON() ([]byte, error) {
	unixFloat := float64(time.Time(t).UnixNano()) / 1e9
	return json.Marshal(unixFloat)
}

func (t *UnixFloatTime) UnmarshalJSON(data []byte) error {
	var unixFloat float64
	if err := json.Unmarshal(data, &unixFloat); err != nil {
		return err
	}

	sec, dec := math.Modf(unixFloat)
	*t = UnixFloatTime(time.Unix(int64(sec), int64(dec*1e9)).UTC())

	return nil
}

type JSONString[T any] struct {
	Value T
}

func (j *JSONString[T]) UnmarshalJSON(data []byte) error {
	var str string
	err := json.Unmarshal(data, &str)
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(str), &j.Value)
	if err != nil {
		return err
	}

	return nil
}

func (j *JSONString[T]) MarshalJSON() ([]byte, error) {
	str, err := json.Marshal(j.Value)
	if err != nil {
		return nil, err
	}

	return json.Marshal(str)
}
