// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.12.4
// source: tunnel_config.proto

package grpcapi

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type PskRequestExperimentalV0 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	WgPubkey    []byte                   `protobuf:"bytes,1,opt,name=wg_pubkey,json=wgPubkey,proto3" json:"wg_pubkey,omitempty"`
	WgPskPubkey []byte                   `protobuf:"bytes,2,opt,name=wg_psk_pubkey,json=wgPskPubkey,proto3" json:"wg_psk_pubkey,omitempty"`
	KemPubkey   *KemPubkeyExperimentalV0 `protobuf:"bytes,3,opt,name=kem_pubkey,json=kemPubkey,proto3" json:"kem_pubkey,omitempty"`
}

func (x *PskRequestExperimentalV0) Reset() {
	*x = PskRequestExperimentalV0{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tunnel_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PskRequestExperimentalV0) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PskRequestExperimentalV0) ProtoMessage() {}

func (x *PskRequestExperimentalV0) ProtoReflect() protoreflect.Message {
	mi := &file_tunnel_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PskRequestExperimentalV0.ProtoReflect.Descriptor instead.
func (*PskRequestExperimentalV0) Descriptor() ([]byte, []int) {
	return file_tunnel_config_proto_rawDescGZIP(), []int{0}
}

func (x *PskRequestExperimentalV0) GetWgPubkey() []byte {
	if x != nil {
		return x.WgPubkey
	}
	return nil
}

func (x *PskRequestExperimentalV0) GetWgPskPubkey() []byte {
	if x != nil {
		return x.WgPskPubkey
	}
	return nil
}

func (x *PskRequestExperimentalV0) GetKemPubkey() *KemPubkeyExperimentalV0 {
	if x != nil {
		return x.KemPubkey
	}
	return nil
}

type KemPubkeyExperimentalV0 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AlgorithmName string `protobuf:"bytes,1,opt,name=algorithm_name,json=algorithmName,proto3" json:"algorithm_name,omitempty"`
	KeyData       []byte `protobuf:"bytes,2,opt,name=key_data,json=keyData,proto3" json:"key_data,omitempty"`
}

func (x *KemPubkeyExperimentalV0) Reset() {
	*x = KemPubkeyExperimentalV0{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tunnel_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KemPubkeyExperimentalV0) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KemPubkeyExperimentalV0) ProtoMessage() {}

func (x *KemPubkeyExperimentalV0) ProtoReflect() protoreflect.Message {
	mi := &file_tunnel_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KemPubkeyExperimentalV0.ProtoReflect.Descriptor instead.
func (*KemPubkeyExperimentalV0) Descriptor() ([]byte, []int) {
	return file_tunnel_config_proto_rawDescGZIP(), []int{1}
}

func (x *KemPubkeyExperimentalV0) GetAlgorithmName() string {
	if x != nil {
		return x.AlgorithmName
	}
	return ""
}

func (x *KemPubkeyExperimentalV0) GetKeyData() []byte {
	if x != nil {
		return x.KeyData
	}
	return nil
}

type PskResponseExperimentalV0 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ciphertext []byte `protobuf:"bytes,1,opt,name=ciphertext,proto3" json:"ciphertext,omitempty"`
}

func (x *PskResponseExperimentalV0) Reset() {
	*x = PskResponseExperimentalV0{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tunnel_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PskResponseExperimentalV0) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PskResponseExperimentalV0) ProtoMessage() {}

func (x *PskResponseExperimentalV0) ProtoReflect() protoreflect.Message {
	mi := &file_tunnel_config_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PskResponseExperimentalV0.ProtoReflect.Descriptor instead.
func (*PskResponseExperimentalV0) Descriptor() ([]byte, []int) {
	return file_tunnel_config_proto_rawDescGZIP(), []int{2}
}

func (x *PskResponseExperimentalV0) GetCiphertext() []byte {
	if x != nil {
		return x.Ciphertext
	}
	return nil
}

type PskRequestExperimentalV1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	WgPubkey    []byte                     `protobuf:"bytes,1,opt,name=wg_pubkey,json=wgPubkey,proto3" json:"wg_pubkey,omitempty"`
	WgPskPubkey []byte                     `protobuf:"bytes,2,opt,name=wg_psk_pubkey,json=wgPskPubkey,proto3" json:"wg_psk_pubkey,omitempty"`
	KemPubkeys  []*KemPubkeyExperimentalV1 `protobuf:"bytes,3,rep,name=kem_pubkeys,json=kemPubkeys,proto3" json:"kem_pubkeys,omitempty"`
}

func (x *PskRequestExperimentalV1) Reset() {
	*x = PskRequestExperimentalV1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tunnel_config_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PskRequestExperimentalV1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PskRequestExperimentalV1) ProtoMessage() {}

func (x *PskRequestExperimentalV1) ProtoReflect() protoreflect.Message {
	mi := &file_tunnel_config_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PskRequestExperimentalV1.ProtoReflect.Descriptor instead.
func (*PskRequestExperimentalV1) Descriptor() ([]byte, []int) {
	return file_tunnel_config_proto_rawDescGZIP(), []int{3}
}

func (x *PskRequestExperimentalV1) GetWgPubkey() []byte {
	if x != nil {
		return x.WgPubkey
	}
	return nil
}

func (x *PskRequestExperimentalV1) GetWgPskPubkey() []byte {
	if x != nil {
		return x.WgPskPubkey
	}
	return nil
}

func (x *PskRequestExperimentalV1) GetKemPubkeys() []*KemPubkeyExperimentalV1 {
	if x != nil {
		return x.KemPubkeys
	}
	return nil
}

type KemPubkeyExperimentalV1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AlgorithmName string `protobuf:"bytes,1,opt,name=algorithm_name,json=algorithmName,proto3" json:"algorithm_name,omitempty"`
	KeyData       []byte `protobuf:"bytes,2,opt,name=key_data,json=keyData,proto3" json:"key_data,omitempty"`
}

func (x *KemPubkeyExperimentalV1) Reset() {
	*x = KemPubkeyExperimentalV1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tunnel_config_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KemPubkeyExperimentalV1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KemPubkeyExperimentalV1) ProtoMessage() {}

func (x *KemPubkeyExperimentalV1) ProtoReflect() protoreflect.Message {
	mi := &file_tunnel_config_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KemPubkeyExperimentalV1.ProtoReflect.Descriptor instead.
func (*KemPubkeyExperimentalV1) Descriptor() ([]byte, []int) {
	return file_tunnel_config_proto_rawDescGZIP(), []int{4}
}

func (x *KemPubkeyExperimentalV1) GetAlgorithmName() string {
	if x != nil {
		return x.AlgorithmName
	}
	return ""
}

func (x *KemPubkeyExperimentalV1) GetKeyData() []byte {
	if x != nil {
		return x.KeyData
	}
	return nil
}

type PskResponseExperimentalV1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ciphertexts [][]byte `protobuf:"bytes,1,rep,name=ciphertexts,proto3" json:"ciphertexts,omitempty"`
}

func (x *PskResponseExperimentalV1) Reset() {
	*x = PskResponseExperimentalV1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tunnel_config_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PskResponseExperimentalV1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PskResponseExperimentalV1) ProtoMessage() {}

func (x *PskResponseExperimentalV1) ProtoReflect() protoreflect.Message {
	mi := &file_tunnel_config_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PskResponseExperimentalV1.ProtoReflect.Descriptor instead.
func (*PskResponseExperimentalV1) Descriptor() ([]byte, []int) {
	return file_tunnel_config_proto_rawDescGZIP(), []int{5}
}

func (x *PskResponseExperimentalV1) GetCiphertexts() [][]byte {
	if x != nil {
		return x.Ciphertexts
	}
	return nil
}

var File_tunnel_config_proto protoreflect.FileDescriptor

var file_tunnel_config_proto_rawDesc = []byte{
	0x0a, 0x13, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0d, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x5f, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x22, 0xa2, 0x01, 0x0a, 0x18, 0x50, 0x73, 0x6b, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x45, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c, 0x56,
	0x30, 0x12, 0x1b, 0x0a, 0x09, 0x77, 0x67, 0x5f, 0x70, 0x75, 0x62, 0x6b, 0x65, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x77, 0x67, 0x50, 0x75, 0x62, 0x6b, 0x65, 0x79, 0x12, 0x22,
	0x0a, 0x0d, 0x77, 0x67, 0x5f, 0x70, 0x73, 0x6b, 0x5f, 0x70, 0x75, 0x62, 0x6b, 0x65, 0x79, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x77, 0x67, 0x50, 0x73, 0x6b, 0x50, 0x75, 0x62, 0x6b,
	0x65, 0x79, 0x12, 0x45, 0x0a, 0x0a, 0x6b, 0x65, 0x6d, 0x5f, 0x70, 0x75, 0x62, 0x6b, 0x65, 0x79,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x26, 0x2e, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x5f,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x4b, 0x65, 0x6d, 0x50, 0x75, 0x62, 0x6b, 0x65, 0x79,
	0x45, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c, 0x56, 0x30, 0x52, 0x09,
	0x6b, 0x65, 0x6d, 0x50, 0x75, 0x62, 0x6b, 0x65, 0x79, 0x22, 0x5b, 0x0a, 0x17, 0x4b, 0x65, 0x6d,
	0x50, 0x75, 0x62, 0x6b, 0x65, 0x79, 0x45, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74,
	0x61, 0x6c, 0x56, 0x30, 0x12, 0x25, 0x0a, 0x0e, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68,
	0x6d, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x61, 0x6c,
	0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x6b,
	0x65, 0x79, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x6b,
	0x65, 0x79, 0x44, 0x61, 0x74, 0x61, 0x22, 0x3b, 0x0a, 0x19, 0x50, 0x73, 0x6b, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x45, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61,
	0x6c, 0x56, 0x30, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74,
	0x65, 0x78, 0x74, 0x22, 0xa4, 0x01, 0x0a, 0x18, 0x50, 0x73, 0x6b, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x45, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c, 0x56, 0x31,
	0x12, 0x1b, 0x0a, 0x09, 0x77, 0x67, 0x5f, 0x70, 0x75, 0x62, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x08, 0x77, 0x67, 0x50, 0x75, 0x62, 0x6b, 0x65, 0x79, 0x12, 0x22, 0x0a,
	0x0d, 0x77, 0x67, 0x5f, 0x70, 0x73, 0x6b, 0x5f, 0x70, 0x75, 0x62, 0x6b, 0x65, 0x79, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x77, 0x67, 0x50, 0x73, 0x6b, 0x50, 0x75, 0x62, 0x6b, 0x65,
	0x79, 0x12, 0x47, 0x0a, 0x0b, 0x6b, 0x65, 0x6d, 0x5f, 0x70, 0x75, 0x62, 0x6b, 0x65, 0x79, 0x73,
	0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x26, 0x2e, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x5f,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x4b, 0x65, 0x6d, 0x50, 0x75, 0x62, 0x6b, 0x65, 0x79,
	0x45, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c, 0x56, 0x31, 0x52, 0x0a,
	0x6b, 0x65, 0x6d, 0x50, 0x75, 0x62, 0x6b, 0x65, 0x79, 0x73, 0x22, 0x5b, 0x0a, 0x17, 0x4b, 0x65,
	0x6d, 0x50, 0x75, 0x62, 0x6b, 0x65, 0x79, 0x45, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e,
	0x74, 0x61, 0x6c, 0x56, 0x31, 0x12, 0x25, 0x0a, 0x0e, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74,
	0x68, 0x6d, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x61,
	0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x19, 0x0a, 0x08,
	0x6b, 0x65, 0x79, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07,
	0x6b, 0x65, 0x79, 0x44, 0x61, 0x74, 0x61, 0x22, 0x3d, 0x0a, 0x19, 0x50, 0x73, 0x6b, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x45, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74,
	0x61, 0x6c, 0x56, 0x31, 0x12, 0x20, 0x0a, 0x0b, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65,
	0x78, 0x74, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0b, 0x63, 0x69, 0x70, 0x68, 0x65,
	0x72, 0x74, 0x65, 0x78, 0x74, 0x73, 0x32, 0xf7, 0x01, 0x0a, 0x11, 0x50, 0x6f, 0x73, 0x74, 0x51,
	0x75, 0x61, 0x6e, 0x74, 0x75, 0x6d, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x12, 0x70, 0x0a, 0x19,
	0x50, 0x73, 0x6b, 0x45, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x45, 0x78, 0x70, 0x65, 0x72,
	0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c, 0x56, 0x30, 0x12, 0x27, 0x2e, 0x74, 0x75, 0x6e, 0x6e,
	0x65, 0x6c, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x50, 0x73, 0x6b, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x45, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c,
	0x56, 0x30, 0x1a, 0x28, 0x2e, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x5f, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x2e, 0x50, 0x73, 0x6b, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x45, 0x78,
	0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c, 0x56, 0x30, 0x22, 0x00, 0x12, 0x70,
	0x0a, 0x19, 0x50, 0x73, 0x6b, 0x45, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x45, 0x78, 0x70,
	0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c, 0x56, 0x31, 0x12, 0x27, 0x2e, 0x74, 0x75,
	0x6e, 0x6e, 0x65, 0x6c, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x50, 0x73, 0x6b, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x45, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74,
	0x61, 0x6c, 0x56, 0x31, 0x1a, 0x28, 0x2e, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x5f, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x2e, 0x50, 0x73, 0x6b, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x45, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c, 0x56, 0x31, 0x22, 0x00,
	0x42, 0x2d, 0x5a, 0x2b, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6d,
	0x75, 0x6c, 0x6c, 0x76, 0x61, 0x64, 0x2f, 0x77, 0x67, 0x2d, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65,
	0x72, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2f, 0x74, 0x75, 0x6e, 0x63, 0x66, 0x67, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_tunnel_config_proto_rawDescOnce sync.Once
	file_tunnel_config_proto_rawDescData = file_tunnel_config_proto_rawDesc
)

func file_tunnel_config_proto_rawDescGZIP() []byte {
	file_tunnel_config_proto_rawDescOnce.Do(func() {
		file_tunnel_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_tunnel_config_proto_rawDescData)
	})
	return file_tunnel_config_proto_rawDescData
}

var file_tunnel_config_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_tunnel_config_proto_goTypes = []interface{}{
	(*PskRequestExperimentalV0)(nil),  // 0: tunnel_config.PskRequestExperimentalV0
	(*KemPubkeyExperimentalV0)(nil),   // 1: tunnel_config.KemPubkeyExperimentalV0
	(*PskResponseExperimentalV0)(nil), // 2: tunnel_config.PskResponseExperimentalV0
	(*PskRequestExperimentalV1)(nil),  // 3: tunnel_config.PskRequestExperimentalV1
	(*KemPubkeyExperimentalV1)(nil),   // 4: tunnel_config.KemPubkeyExperimentalV1
	(*PskResponseExperimentalV1)(nil), // 5: tunnel_config.PskResponseExperimentalV1
}
var file_tunnel_config_proto_depIdxs = []int32{
	1, // 0: tunnel_config.PskRequestExperimentalV0.kem_pubkey:type_name -> tunnel_config.KemPubkeyExperimentalV0
	4, // 1: tunnel_config.PskRequestExperimentalV1.kem_pubkeys:type_name -> tunnel_config.KemPubkeyExperimentalV1
	0, // 2: tunnel_config.PostQuantumSecure.PskExchangeExperimentalV0:input_type -> tunnel_config.PskRequestExperimentalV0
	3, // 3: tunnel_config.PostQuantumSecure.PskExchangeExperimentalV1:input_type -> tunnel_config.PskRequestExperimentalV1
	2, // 4: tunnel_config.PostQuantumSecure.PskExchangeExperimentalV0:output_type -> tunnel_config.PskResponseExperimentalV0
	5, // 5: tunnel_config.PostQuantumSecure.PskExchangeExperimentalV1:output_type -> tunnel_config.PskResponseExperimentalV1
	4, // [4:6] is the sub-list for method output_type
	2, // [2:4] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_tunnel_config_proto_init() }
func file_tunnel_config_proto_init() {
	if File_tunnel_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_tunnel_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PskRequestExperimentalV0); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_tunnel_config_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KemPubkeyExperimentalV0); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_tunnel_config_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PskResponseExperimentalV0); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_tunnel_config_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PskRequestExperimentalV1); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_tunnel_config_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KemPubkeyExperimentalV1); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_tunnel_config_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PskResponseExperimentalV1); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_tunnel_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_tunnel_config_proto_goTypes,
		DependencyIndexes: file_tunnel_config_proto_depIdxs,
		MessageInfos:      file_tunnel_config_proto_msgTypes,
	}.Build()
	File_tunnel_config_proto = out.File
	file_tunnel_config_proto_rawDesc = nil
	file_tunnel_config_proto_goTypes = nil
	file_tunnel_config_proto_depIdxs = nil
}
