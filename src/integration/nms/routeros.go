package nms

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "watcher-agent/src/domain/snmp"
)

type RouterOSProvisionRequest struct {
    AgentID    string         `json:"agent_id"`
    DeviceType string         `json:"device_type"`
    Serial     string         `json:"serial"`
    DeviceIP   string         `json:"device_ip"`
    SNMP       snmp.SNMPReadResult `json:"snmp"`
}

type RouterOSProvisionResponse struct {
    Script string `json:"script"`
}

func (c *NMSClient) GetRouterOSProvisionScript(req RouterOSProvisionRequest) (string, error) {
    b, _ := json.Marshal(req)
    httpReq, _ := http.NewRequest("POST", c.cfg.BaseURL+"/api/agent/provision/routeros", bytes.NewReader(b))
    httpReq.Header.Set("Authorization", "Bearer "+c.cfg.Token)
    httpReq.Header.Set("Content-Type", "application/json")

    resp, err := c.hc.Do(httpReq)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    if resp.StatusCode != 200 {
        return "", fmt.Errorf("nms error %d: %s", resp.StatusCode, string(body))
    }

    var out RouterOSProvisionResponse
    if err := json.Unmarshal(body, &out); err != nil {
        return "", err
    }
    return out.Script, nil
}
