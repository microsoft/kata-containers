// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: csi.proto

package grpc

import (
	bytes "bytes"
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
	reflect "reflect"
	strings "strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type VolumeUsage_Unit int32

const (
	VolumeUsage_UNKNOWN VolumeUsage_Unit = 0
	VolumeUsage_BYTES   VolumeUsage_Unit = 1
	VolumeUsage_INODES  VolumeUsage_Unit = 2
)

var VolumeUsage_Unit_name = map[int32]string{
	0: "UNKNOWN",
	1: "BYTES",
	2: "INODES",
}

var VolumeUsage_Unit_value = map[string]int32{
	"UNKNOWN": 0,
	"BYTES":   1,
	"INODES":  2,
}

func (x VolumeUsage_Unit) String() string {
	return proto.EnumName(VolumeUsage_Unit_name, int32(x))
}

func (VolumeUsage_Unit) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_e099a7ef79268152, []int{1, 0}
}

// This should be kept in sync with CSI NodeGetVolumeStatsResponse (https://github.com/container-storage-interface/spec/blob/v1.5.0/csi.proto)
type VolumeStatsResponse struct {
	// This field is OPTIONAL.
	Usage []*VolumeUsage `protobuf:"bytes,1,rep,name=usage,proto3" json:"usage,omitempty"`
	// Information about the current condition of the volume.
	// This field is OPTIONAL.
	// This field MUST be specified if the VOLUME_CONDITION node
	// capability is supported.
	VolumeCondition      *VolumeCondition `protobuf:"bytes,2,opt,name=volume_condition,json=volumeCondition,proto3" json:"volume_condition,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *VolumeStatsResponse) Reset()      { *m = VolumeStatsResponse{} }
func (*VolumeStatsResponse) ProtoMessage() {}
func (*VolumeStatsResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_e099a7ef79268152, []int{0}
}
func (m *VolumeStatsResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *VolumeStatsResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_VolumeStatsResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *VolumeStatsResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VolumeStatsResponse.Merge(m, src)
}
func (m *VolumeStatsResponse) XXX_Size() int {
	return m.Size()
}
func (m *VolumeStatsResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_VolumeStatsResponse.DiscardUnknown(m)
}

var xxx_messageInfo_VolumeStatsResponse proto.InternalMessageInfo

type VolumeUsage struct {
	// The available capacity in specified Unit. This field is OPTIONAL.
	// The value of this field MUST NOT be negative.
	Available uint64 `protobuf:"varint,1,opt,name=available,proto3" json:"available,omitempty"`
	// The total capacity in specified Unit. This field is REQUIRED.
	// The value of this field MUST NOT be negative.
	Total uint64 `protobuf:"varint,2,opt,name=total,proto3" json:"total,omitempty"`
	// The used capacity in specified Unit. This field is OPTIONAL.
	// The value of this field MUST NOT be negative.
	Used uint64 `protobuf:"varint,3,opt,name=used,proto3" json:"used,omitempty"`
	// Units by which values are measured. This field is REQUIRED.
	Unit                 VolumeUsage_Unit `protobuf:"varint,4,opt,name=unit,proto3,enum=grpc.VolumeUsage_Unit" json:"unit,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *VolumeUsage) Reset()      { *m = VolumeUsage{} }
func (*VolumeUsage) ProtoMessage() {}
func (*VolumeUsage) Descriptor() ([]byte, []int) {
	return fileDescriptor_e099a7ef79268152, []int{1}
}
func (m *VolumeUsage) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *VolumeUsage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_VolumeUsage.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *VolumeUsage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VolumeUsage.Merge(m, src)
}
func (m *VolumeUsage) XXX_Size() int {
	return m.Size()
}
func (m *VolumeUsage) XXX_DiscardUnknown() {
	xxx_messageInfo_VolumeUsage.DiscardUnknown(m)
}

var xxx_messageInfo_VolumeUsage proto.InternalMessageInfo

// VolumeCondition represents the current condition of a volume.
type VolumeCondition struct {
	// Normal volumes are available for use and operating optimally.
	// An abnormal volume does not meet these criteria.
	// This field is REQUIRED.
	Abnormal bool `protobuf:"varint,1,opt,name=abnormal,proto3" json:"abnormal,omitempty"`
	// The message describing the condition of the volume.
	// This field is REQUIRED.
	Message              string   `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *VolumeCondition) Reset()      { *m = VolumeCondition{} }
func (*VolumeCondition) ProtoMessage() {}
func (*VolumeCondition) Descriptor() ([]byte, []int) {
	return fileDescriptor_e099a7ef79268152, []int{2}
}
func (m *VolumeCondition) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *VolumeCondition) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_VolumeCondition.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *VolumeCondition) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VolumeCondition.Merge(m, src)
}
func (m *VolumeCondition) XXX_Size() int {
	return m.Size()
}
func (m *VolumeCondition) XXX_DiscardUnknown() {
	xxx_messageInfo_VolumeCondition.DiscardUnknown(m)
}

var xxx_messageInfo_VolumeCondition proto.InternalMessageInfo

func init() {
	proto.RegisterEnum("grpc.VolumeUsage_Unit", VolumeUsage_Unit_name, VolumeUsage_Unit_value)
	proto.RegisterType((*VolumeStatsResponse)(nil), "grpc.VolumeStatsResponse")
	proto.RegisterType((*VolumeUsage)(nil), "grpc.VolumeUsage")
	proto.RegisterType((*VolumeCondition)(nil), "grpc.VolumeCondition")
}

func init() { proto.RegisterFile("csi.proto", fileDescriptor_e099a7ef79268152) }

var fileDescriptor_e099a7ef79268152 = []byte{
	// 410 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x64, 0x92, 0xcf, 0x6b, 0xd4, 0x40,
	0x14, 0xc7, 0xf7, 0xb5, 0xd9, 0xb6, 0xfb, 0x16, 0xec, 0x3a, 0xfe, 0x20, 0x14, 0x19, 0x96, 0x5c,
	0x0c, 0x05, 0x13, 0x58, 0xff, 0x01, 0xa9, 0x16, 0x11, 0x21, 0x85, 0x59, 0x57, 0xd1, 0x83, 0x32,
	0x49, 0xc7, 0x38, 0x34, 0x99, 0x09, 0x99, 0x49, 0xce, 0x3d, 0xfa, 0xa7, 0x78, 0xf1, 0xee, 0xd1,
	0x63, 0x8f, 0x1e, 0x3d, 0xba, 0xf9, 0x2b, 0x3c, 0x4a, 0x26, 0x54, 0xd7, 0xee, 0xed, 0x7d, 0xbe,
	0xdf, 0x37, 0xef, 0x17, 0x83, 0x93, 0xcc, 0xc8, 0xa8, 0xaa, 0xb5, 0xd5, 0xc4, 0xcb, 0xeb, 0x2a,
	0x3b, 0x0a, 0x72, 0x9d, 0xeb, 0xd8, 0x29, 0x69, 0xf3, 0x31, 0xee, 0xc9, 0x81, 0x8b, 0x86, 0xcc,
	0xe0, 0x12, 0xf0, 0xce, 0x6b, 0x5d, 0x34, 0xa5, 0x58, 0x5a, 0x6e, 0x0d, 0x13, 0xa6, 0xd2, 0xca,
	0x08, 0xf2, 0x10, 0xc7, 0x8d, 0xe1, 0xb9, 0xf0, 0x61, 0xbe, 0x1b, 0x4e, 0x17, 0xb7, 0xa3, 0xbe,
	0x62, 0x34, 0x64, 0xae, 0x7a, 0x83, 0x0d, 0x3e, 0x79, 0x82, 0xb3, 0xd6, 0xa9, 0x1f, 0x32, 0xad,
	0xce, 0xa5, 0x95, 0x5a, 0xf9, 0x3b, 0x73, 0x08, 0xa7, 0x8b, 0x7b, 0x9b, 0x6f, 0x9e, 0x5e, 0x9b,
	0xec, 0xb0, 0xfd, 0x5f, 0x08, 0xbe, 0x02, 0x4e, 0x37, 0x0a, 0x93, 0x07, 0x38, 0xe1, 0x2d, 0x97,
	0x05, 0x4f, 0x8b, 0xbe, 0x3d, 0x84, 0x1e, 0xfb, 0x27, 0x90, 0xbb, 0x38, 0xb6, 0xda, 0xf2, 0xc2,
	0x35, 0xf1, 0xd8, 0x00, 0x84, 0xa0, 0xd7, 0x18, 0x71, 0xee, 0xef, 0x3a, 0xd1, 0xc5, 0xe4, 0x18,
	0xbd, 0x46, 0x49, 0xeb, 0x7b, 0x73, 0x08, 0x6f, 0x2d, 0xee, 0x6f, 0x6d, 0x10, 0xad, 0x94, 0xb4,
	0xcc, 0xe5, 0x04, 0xc7, 0xe8, 0xf5, 0x44, 0xa6, 0xb8, 0xbf, 0x4a, 0x5e, 0x26, 0x67, 0x6f, 0x92,
	0xd9, 0x88, 0x4c, 0x70, 0x7c, 0xf2, 0xf6, 0xd5, 0xe9, 0x72, 0x06, 0x04, 0x71, 0xef, 0x45, 0x72,
	0xf6, 0xec, 0x74, 0x39, 0xdb, 0x09, 0x9e, 0xe3, 0xe1, 0x8d, 0x9d, 0xc8, 0x11, 0x1e, 0xf0, 0x54,
	0xe9, 0xba, 0xe4, 0x85, 0x9b, 0xf8, 0x80, 0xfd, 0x65, 0xe2, 0xe3, 0x7e, 0x29, 0x8c, 0xbb, 0x65,
	0x3f, 0xf2, 0x84, 0x5d, 0xe3, 0xc9, 0x67, 0xb8, 0x5a, 0xd3, 0xd1, 0xcf, 0x35, 0x1d, 0xfd, 0x5e,
	0x53, 0xb8, 0xec, 0x28, 0x7c, 0xe9, 0x28, 0x7c, 0xeb, 0x28, 0x7c, 0xef, 0x28, 0x5c, 0x75, 0x14,
	0x7e, 0x74, 0x14, 0x7e, 0x75, 0x14, 0xde, 0xbd, 0xcf, 0xa5, 0xfd, 0xd4, 0xa4, 0x51, 0xa6, 0xcb,
	0xf8, 0x82, 0x5b, 0xfe, 0x28, 0xd3, 0xca, 0x72, 0xa9, 0x44, 0x6d, 0xb6, 0xd8, 0xd4, 0x59, 0x5c,
	0x37, 0xca, 0xca, 0x52, 0xc4, 0xad, 0xac, 0xed, 0x86, 0x55, 0x5d, 0xe4, 0x31, 0xcf, 0x85, 0xb2,
	0xc3, 0xaf, 0xc8, 0x74, 0x61, 0xe2, 0xfe, 0x2c, 0xe9, 0x9e, 0xe3, 0xc7, 0x7f, 0x02, 0x00, 0x00,
	0xff, 0xff, 0x62, 0xcb, 0xed, 0xf6, 0x44, 0x02, 0x00, 0x00,
}

func (this *VolumeStatsResponse) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*VolumeStatsResponse)
	if !ok {
		that2, ok := that.(VolumeStatsResponse)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if len(this.Usage) != len(that1.Usage) {
		return false
	}
	for i := range this.Usage {
		if !this.Usage[i].Equal(that1.Usage[i]) {
			return false
		}
	}
	if !this.VolumeCondition.Equal(that1.VolumeCondition) {
		return false
	}
	if !bytes.Equal(this.XXX_unrecognized, that1.XXX_unrecognized) {
		return false
	}
	return true
}
func (this *VolumeUsage) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*VolumeUsage)
	if !ok {
		that2, ok := that.(VolumeUsage)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.Available != that1.Available {
		return false
	}
	if this.Total != that1.Total {
		return false
	}
	if this.Used != that1.Used {
		return false
	}
	if this.Unit != that1.Unit {
		return false
	}
	if !bytes.Equal(this.XXX_unrecognized, that1.XXX_unrecognized) {
		return false
	}
	return true
}
func (this *VolumeCondition) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*VolumeCondition)
	if !ok {
		that2, ok := that.(VolumeCondition)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.Abnormal != that1.Abnormal {
		return false
	}
	if this.Message != that1.Message {
		return false
	}
	if !bytes.Equal(this.XXX_unrecognized, that1.XXX_unrecognized) {
		return false
	}
	return true
}
func (m *VolumeStatsResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *VolumeStatsResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *VolumeStatsResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.VolumeCondition != nil {
		{
			size, err := m.VolumeCondition.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintCsi(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if len(m.Usage) > 0 {
		for iNdEx := len(m.Usage) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.Usage[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintCsi(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func (m *VolumeUsage) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *VolumeUsage) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *VolumeUsage) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.Unit != 0 {
		i = encodeVarintCsi(dAtA, i, uint64(m.Unit))
		i--
		dAtA[i] = 0x20
	}
	if m.Used != 0 {
		i = encodeVarintCsi(dAtA, i, uint64(m.Used))
		i--
		dAtA[i] = 0x18
	}
	if m.Total != 0 {
		i = encodeVarintCsi(dAtA, i, uint64(m.Total))
		i--
		dAtA[i] = 0x10
	}
	if m.Available != 0 {
		i = encodeVarintCsi(dAtA, i, uint64(m.Available))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *VolumeCondition) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *VolumeCondition) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *VolumeCondition) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.Message) > 0 {
		i -= len(m.Message)
		copy(dAtA[i:], m.Message)
		i = encodeVarintCsi(dAtA, i, uint64(len(m.Message)))
		i--
		dAtA[i] = 0x12
	}
	if m.Abnormal {
		i--
		if m.Abnormal {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func encodeVarintCsi(dAtA []byte, offset int, v uint64) int {
	offset -= sovCsi(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func NewPopulatedVolumeStatsResponse(r randyCsi, easy bool) *VolumeStatsResponse {
	this := &VolumeStatsResponse{}
	if r.Intn(5) != 0 {
		v1 := r.Intn(5)
		this.Usage = make([]*VolumeUsage, v1)
		for i := 0; i < v1; i++ {
			this.Usage[i] = NewPopulatedVolumeUsage(r, easy)
		}
	}
	if r.Intn(5) != 0 {
		this.VolumeCondition = NewPopulatedVolumeCondition(r, easy)
	}
	if !easy && r.Intn(10) != 0 {
		this.XXX_unrecognized = randUnrecognizedCsi(r, 3)
	}
	return this
}

func NewPopulatedVolumeUsage(r randyCsi, easy bool) *VolumeUsage {
	this := &VolumeUsage{}
	this.Available = uint64(uint64(r.Uint32()))
	this.Total = uint64(uint64(r.Uint32()))
	this.Used = uint64(uint64(r.Uint32()))
	this.Unit = VolumeUsage_Unit([]int32{0, 1, 2}[r.Intn(3)])
	if !easy && r.Intn(10) != 0 {
		this.XXX_unrecognized = randUnrecognizedCsi(r, 5)
	}
	return this
}

func NewPopulatedVolumeCondition(r randyCsi, easy bool) *VolumeCondition {
	this := &VolumeCondition{}
	this.Abnormal = bool(bool(r.Intn(2) == 0))
	this.Message = string(randStringCsi(r))
	if !easy && r.Intn(10) != 0 {
		this.XXX_unrecognized = randUnrecognizedCsi(r, 3)
	}
	return this
}

type randyCsi interface {
	Float32() float32
	Float64() float64
	Int63() int64
	Int31() int32
	Uint32() uint32
	Intn(n int) int
}

func randUTF8RuneCsi(r randyCsi) rune {
	ru := r.Intn(62)
	if ru < 10 {
		return rune(ru + 48)
	} else if ru < 36 {
		return rune(ru + 55)
	}
	return rune(ru + 61)
}
func randStringCsi(r randyCsi) string {
	v2 := r.Intn(100)
	tmps := make([]rune, v2)
	for i := 0; i < v2; i++ {
		tmps[i] = randUTF8RuneCsi(r)
	}
	return string(tmps)
}
func randUnrecognizedCsi(r randyCsi, maxFieldNumber int) (dAtA []byte) {
	l := r.Intn(5)
	for i := 0; i < l; i++ {
		wire := r.Intn(4)
		if wire == 3 {
			wire = 5
		}
		fieldNumber := maxFieldNumber + r.Intn(100)
		dAtA = randFieldCsi(dAtA, r, fieldNumber, wire)
	}
	return dAtA
}
func randFieldCsi(dAtA []byte, r randyCsi, fieldNumber int, wire int) []byte {
	key := uint32(fieldNumber)<<3 | uint32(wire)
	switch wire {
	case 0:
		dAtA = encodeVarintPopulateCsi(dAtA, uint64(key))
		v3 := r.Int63()
		if r.Intn(2) == 0 {
			v3 *= -1
		}
		dAtA = encodeVarintPopulateCsi(dAtA, uint64(v3))
	case 1:
		dAtA = encodeVarintPopulateCsi(dAtA, uint64(key))
		dAtA = append(dAtA, byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)))
	case 2:
		dAtA = encodeVarintPopulateCsi(dAtA, uint64(key))
		ll := r.Intn(100)
		dAtA = encodeVarintPopulateCsi(dAtA, uint64(ll))
		for j := 0; j < ll; j++ {
			dAtA = append(dAtA, byte(r.Intn(256)))
		}
	default:
		dAtA = encodeVarintPopulateCsi(dAtA, uint64(key))
		dAtA = append(dAtA, byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)))
	}
	return dAtA
}
func encodeVarintPopulateCsi(dAtA []byte, v uint64) []byte {
	for v >= 1<<7 {
		dAtA = append(dAtA, uint8(uint64(v)&0x7f|0x80))
		v >>= 7
	}
	dAtA = append(dAtA, uint8(v))
	return dAtA
}
func (m *VolumeStatsResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.Usage) > 0 {
		for _, e := range m.Usage {
			l = e.Size()
			n += 1 + l + sovCsi(uint64(l))
		}
	}
	if m.VolumeCondition != nil {
		l = m.VolumeCondition.Size()
		n += 1 + l + sovCsi(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *VolumeUsage) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Available != 0 {
		n += 1 + sovCsi(uint64(m.Available))
	}
	if m.Total != 0 {
		n += 1 + sovCsi(uint64(m.Total))
	}
	if m.Used != 0 {
		n += 1 + sovCsi(uint64(m.Used))
	}
	if m.Unit != 0 {
		n += 1 + sovCsi(uint64(m.Unit))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *VolumeCondition) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Abnormal {
		n += 2
	}
	l = len(m.Message)
	if l > 0 {
		n += 1 + l + sovCsi(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovCsi(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozCsi(x uint64) (n int) {
	return sovCsi(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *VolumeStatsResponse) String() string {
	if this == nil {
		return "nil"
	}
	repeatedStringForUsage := "[]*VolumeUsage{"
	for _, f := range this.Usage {
		repeatedStringForUsage += strings.Replace(f.String(), "VolumeUsage", "VolumeUsage", 1) + ","
	}
	repeatedStringForUsage += "}"
	s := strings.Join([]string{`&VolumeStatsResponse{`,
		`Usage:` + repeatedStringForUsage + `,`,
		`VolumeCondition:` + strings.Replace(this.VolumeCondition.String(), "VolumeCondition", "VolumeCondition", 1) + `,`,
		`XXX_unrecognized:` + fmt.Sprintf("%v", this.XXX_unrecognized) + `,`,
		`}`,
	}, "")
	return s
}
func (this *VolumeUsage) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&VolumeUsage{`,
		`Available:` + fmt.Sprintf("%v", this.Available) + `,`,
		`Total:` + fmt.Sprintf("%v", this.Total) + `,`,
		`Used:` + fmt.Sprintf("%v", this.Used) + `,`,
		`Unit:` + fmt.Sprintf("%v", this.Unit) + `,`,
		`XXX_unrecognized:` + fmt.Sprintf("%v", this.XXX_unrecognized) + `,`,
		`}`,
	}, "")
	return s
}
func (this *VolumeCondition) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&VolumeCondition{`,
		`Abnormal:` + fmt.Sprintf("%v", this.Abnormal) + `,`,
		`Message:` + fmt.Sprintf("%v", this.Message) + `,`,
		`XXX_unrecognized:` + fmt.Sprintf("%v", this.XXX_unrecognized) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringCsi(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *VolumeStatsResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCsi
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: VolumeStatsResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: VolumeStatsResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Usage", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCsi
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthCsi
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthCsi
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Usage = append(m.Usage, &VolumeUsage{})
			if err := m.Usage[len(m.Usage)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field VolumeCondition", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCsi
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthCsi
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthCsi
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.VolumeCondition == nil {
				m.VolumeCondition = &VolumeCondition{}
			}
			if err := m.VolumeCondition.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipCsi(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthCsi
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *VolumeUsage) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCsi
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: VolumeUsage: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: VolumeUsage: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Available", wireType)
			}
			m.Available = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCsi
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Available |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Total", wireType)
			}
			m.Total = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCsi
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Total |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Used", wireType)
			}
			m.Used = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCsi
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Used |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Unit", wireType)
			}
			m.Unit = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCsi
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Unit |= VolumeUsage_Unit(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipCsi(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthCsi
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *VolumeCondition) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCsi
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: VolumeCondition: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: VolumeCondition: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Abnormal", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCsi
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.Abnormal = bool(v != 0)
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Message", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCsi
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCsi
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthCsi
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Message = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipCsi(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthCsi
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipCsi(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowCsi
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowCsi
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowCsi
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthCsi
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupCsi
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthCsi
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthCsi        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowCsi          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupCsi = fmt.Errorf("proto: unexpected end of group")
)