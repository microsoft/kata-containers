/*
Cloud Hypervisor API

Local HTTP based API for managing and inspecting a cloud-hypervisor virtual machine.

API version: 0.3.0
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package openapi

import (
	"encoding/json"
)

// checks if the PlatformConfig type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &PlatformConfig{}

// PlatformConfig struct for PlatformConfig
type PlatformConfig struct {
	NumPciSegments *int32 `json:"num_pci_segments,omitempty"`
	IommuSegments []int32 `json:"iommu_segments,omitempty"`
	SerialNumber *string `json:"serial_number,omitempty"`
	Uuid *string `json:"uuid,omitempty"`
	OemStrings []string `json:"oem_strings,omitempty"`
	Tdx *bool `json:"tdx,omitempty"`
}

// NewPlatformConfig instantiates a new PlatformConfig object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewPlatformConfig() *PlatformConfig {
	this := PlatformConfig{}
	var tdx bool = false
	this.Tdx = &tdx
	return &this
}

// NewPlatformConfigWithDefaults instantiates a new PlatformConfig object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewPlatformConfigWithDefaults() *PlatformConfig {
	this := PlatformConfig{}
	var tdx bool = false
	this.Tdx = &tdx
	return &this
}

// GetNumPciSegments returns the NumPciSegments field value if set, zero value otherwise.
func (o *PlatformConfig) GetNumPciSegments() int32 {
	if o == nil || IsNil(o.NumPciSegments) {
		var ret int32
		return ret
	}
	return *o.NumPciSegments
}

// GetNumPciSegmentsOk returns a tuple with the NumPciSegments field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PlatformConfig) GetNumPciSegmentsOk() (*int32, bool) {
	if o == nil || IsNil(o.NumPciSegments) {
		return nil, false
	}
	return o.NumPciSegments, true
}

// HasNumPciSegments returns a boolean if a field has been set.
func (o *PlatformConfig) HasNumPciSegments() bool {
	if o != nil && !IsNil(o.NumPciSegments) {
		return true
	}

	return false
}

// SetNumPciSegments gets a reference to the given int32 and assigns it to the NumPciSegments field.
func (o *PlatformConfig) SetNumPciSegments(v int32) {
	o.NumPciSegments = &v
}

// GetIommuSegments returns the IommuSegments field value if set, zero value otherwise.
func (o *PlatformConfig) GetIommuSegments() []int32 {
	if o == nil || IsNil(o.IommuSegments) {
		var ret []int32
		return ret
	}
	return o.IommuSegments
}

// GetIommuSegmentsOk returns a tuple with the IommuSegments field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PlatformConfig) GetIommuSegmentsOk() ([]int32, bool) {
	if o == nil || IsNil(o.IommuSegments) {
		return nil, false
	}
	return o.IommuSegments, true
}

// HasIommuSegments returns a boolean if a field has been set.
func (o *PlatformConfig) HasIommuSegments() bool {
	if o != nil && !IsNil(o.IommuSegments) {
		return true
	}

	return false
}

// SetIommuSegments gets a reference to the given []int32 and assigns it to the IommuSegments field.
func (o *PlatformConfig) SetIommuSegments(v []int32) {
	o.IommuSegments = v
}

// GetSerialNumber returns the SerialNumber field value if set, zero value otherwise.
func (o *PlatformConfig) GetSerialNumber() string {
	if o == nil || IsNil(o.SerialNumber) {
		var ret string
		return ret
	}
	return *o.SerialNumber
}

// GetSerialNumberOk returns a tuple with the SerialNumber field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PlatformConfig) GetSerialNumberOk() (*string, bool) {
	if o == nil || IsNil(o.SerialNumber) {
		return nil, false
	}
	return o.SerialNumber, true
}

// HasSerialNumber returns a boolean if a field has been set.
func (o *PlatformConfig) HasSerialNumber() bool {
	if o != nil && !IsNil(o.SerialNumber) {
		return true
	}

	return false
}

// SetSerialNumber gets a reference to the given string and assigns it to the SerialNumber field.
func (o *PlatformConfig) SetSerialNumber(v string) {
	o.SerialNumber = &v
}

// GetUuid returns the Uuid field value if set, zero value otherwise.
func (o *PlatformConfig) GetUuid() string {
	if o == nil || IsNil(o.Uuid) {
		var ret string
		return ret
	}
	return *o.Uuid
}

// GetUuidOk returns a tuple with the Uuid field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PlatformConfig) GetUuidOk() (*string, bool) {
	if o == nil || IsNil(o.Uuid) {
		return nil, false
	}
	return o.Uuid, true
}

// HasUuid returns a boolean if a field has been set.
func (o *PlatformConfig) HasUuid() bool {
	if o != nil && !IsNil(o.Uuid) {
		return true
	}

	return false
}

// SetUuid gets a reference to the given string and assigns it to the Uuid field.
func (o *PlatformConfig) SetUuid(v string) {
	o.Uuid = &v
}

// GetOemStrings returns the OemStrings field value if set, zero value otherwise.
func (o *PlatformConfig) GetOemStrings() []string {
	if o == nil || IsNil(o.OemStrings) {
		var ret []string
		return ret
	}
	return o.OemStrings
}

// GetOemStringsOk returns a tuple with the OemStrings field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PlatformConfig) GetOemStringsOk() ([]string, bool) {
	if o == nil || IsNil(o.OemStrings) {
		return nil, false
	}
	return o.OemStrings, true
}

// HasOemStrings returns a boolean if a field has been set.
func (o *PlatformConfig) HasOemStrings() bool {
	if o != nil && !IsNil(o.OemStrings) {
		return true
	}

	return false
}

// SetOemStrings gets a reference to the given []string and assigns it to the OemStrings field.
func (o *PlatformConfig) SetOemStrings(v []string) {
	o.OemStrings = v
}

// GetTdx returns the Tdx field value if set, zero value otherwise.
func (o *PlatformConfig) GetTdx() bool {
	if o == nil || IsNil(o.Tdx) {
		var ret bool
		return ret
	}
	return *o.Tdx
}

// GetTdxOk returns a tuple with the Tdx field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PlatformConfig) GetTdxOk() (*bool, bool) {
	if o == nil || IsNil(o.Tdx) {
		return nil, false
	}
	return o.Tdx, true
}

// HasTdx returns a boolean if a field has been set.
func (o *PlatformConfig) HasTdx() bool {
	if o != nil && !IsNil(o.Tdx) {
		return true
	}

	return false
}

// SetTdx gets a reference to the given bool and assigns it to the Tdx field.
func (o *PlatformConfig) SetTdx(v bool) {
	o.Tdx = &v
}

func (o PlatformConfig) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o PlatformConfig) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.NumPciSegments) {
		toSerialize["num_pci_segments"] = o.NumPciSegments
	}
	if !IsNil(o.IommuSegments) {
		toSerialize["iommu_segments"] = o.IommuSegments
	}
	if !IsNil(o.SerialNumber) {
		toSerialize["serial_number"] = o.SerialNumber
	}
	if !IsNil(o.Uuid) {
		toSerialize["uuid"] = o.Uuid
	}
	if !IsNil(o.OemStrings) {
		toSerialize["oem_strings"] = o.OemStrings
	}
	if !IsNil(o.Tdx) {
		toSerialize["tdx"] = o.Tdx
	}
	return toSerialize, nil
}

type NullablePlatformConfig struct {
	value *PlatformConfig
	isSet bool
}

func (v NullablePlatformConfig) Get() *PlatformConfig {
	return v.value
}

func (v *NullablePlatformConfig) Set(val *PlatformConfig) {
	v.value = val
	v.isSet = true
}

func (v NullablePlatformConfig) IsSet() bool {
	return v.isSet
}

func (v *NullablePlatformConfig) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullablePlatformConfig(val *PlatformConfig) *NullablePlatformConfig {
	return &NullablePlatformConfig{value: val, isSet: true}
}

func (v NullablePlatformConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullablePlatformConfig) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


