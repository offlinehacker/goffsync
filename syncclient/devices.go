package syncclient

import (
	"context"
	"fmt"
)

type registerDeviceRequestSchema struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// RegisterDevice registers a new device with the given name and type.
// It requires a valid LoginSession and returns an error if registration fails.
func (f *Client) RegisterDevice(ctx context.Context, session LoginSession, deviceName, deviceType string) error {
	debug("Registering device", "name", deviceName, "type", deviceType)

	body := registerDeviceRequestSchema{
		Name: deviceName,
		Type: deviceType,
	}

	_, _, err := f.requestWithHawkToken(ctx, "POST", "/account/device", body, session.SessionToken, "sessionToken")
	if err != nil {
		return fmt.Errorf("failed to register device: %w", err)
	}

	debug("Device registered", "name", deviceName)

	return nil
}
