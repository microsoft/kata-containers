package openapi

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVmConfigRTCJSON(t *testing.T) {
	configuredRTC := NewRtcConfig()
	configuredRTC.SetIommu(true)
	configuredRTC.SetId("rtc0")
	configuredRTC.SetPciSegment(1)
	configuredRTC.SetPciDeviceId(8)

	tests := []struct {
		name     string
		rtc      *RtcConfig
		wantJSON string
	}{
		{
			name: "legacy without RTC",
		},
		{
			name:     "default RTC",
			rtc:      NewRtcConfig(),
			wantJSON: `{"iommu":false,"pci_segment":0}`,
		},
		{
			name:     "configured RTC",
			rtc:      configuredRTC,
			wantJSON: `{"iommu":true,"id":"rtc0","pci_segment":1,"pci_device_id":8}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := NewVmConfig(*NewPayloadConfig())
			config.Rtc = test.rtc

			encoded, err := json.Marshal(config)
			require.NoError(t, err)
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(encoded, &fields))
			if test.rtc == nil {
				assert.NotContains(t, fields, "rtc")
			} else {
				require.Contains(t, fields, "rtc")
				assert.JSONEq(t, test.wantJSON, string(fields["rtc"]))
			}

			var decoded VmConfig
			require.NoError(t, json.Unmarshal(encoded, &decoded))
			assert.Equal(t, config, &decoded)
		})
	}
}
