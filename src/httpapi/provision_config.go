package httpapi

type ProvisionConfig struct {
	AgentID     string
	DeviceTypes map[string]DeviceTypeConfig
}

type DeviceTypeConfig struct {
	Community string `json:"community"`
}
