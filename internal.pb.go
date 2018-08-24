// Code generated by protoc-gen-go. DO NOT EDIT.
// source: internal.proto

package mainflux

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type AccessReq struct {
	Token                string   `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	ChanID               uint64   `protobuf:"varint,2,opt,name=chanID,proto3" json:"chanID,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AccessReq) Reset()         { *m = AccessReq{} }
func (m *AccessReq) String() string { return proto.CompactTextString(m) }
func (*AccessReq) ProtoMessage()    {}
func (*AccessReq) Descriptor() ([]byte, []int) {
	return fileDescriptor_internal_50ed0f35f4250621, []int{0}
}
func (m *AccessReq) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AccessReq.Unmarshal(m, b)
}
func (m *AccessReq) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AccessReq.Marshal(b, m, deterministic)
}
func (dst *AccessReq) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AccessReq.Merge(dst, src)
}
func (m *AccessReq) XXX_Size() int {
	return xxx_messageInfo_AccessReq.Size(m)
}
func (m *AccessReq) XXX_DiscardUnknown() {
	xxx_messageInfo_AccessReq.DiscardUnknown(m)
}

var xxx_messageInfo_AccessReq proto.InternalMessageInfo

func (m *AccessReq) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

func (m *AccessReq) GetChanID() uint64 {
	if m != nil {
		return m.ChanID
	}
	return 0
}

type ThingID struct {
	Value                uint64   `protobuf:"varint,1,opt,name=value,proto3" json:"value,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ThingID) Reset()         { *m = ThingID{} }
func (m *ThingID) String() string { return proto.CompactTextString(m) }
func (*ThingID) ProtoMessage()    {}
func (*ThingID) Descriptor() ([]byte, []int) {
	return fileDescriptor_internal_50ed0f35f4250621, []int{1}
}
func (m *ThingID) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ThingID.Unmarshal(m, b)
}
func (m *ThingID) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ThingID.Marshal(b, m, deterministic)
}
func (dst *ThingID) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ThingID.Merge(dst, src)
}
func (m *ThingID) XXX_Size() int {
	return xxx_messageInfo_ThingID.Size(m)
}
func (m *ThingID) XXX_DiscardUnknown() {
	xxx_messageInfo_ThingID.DiscardUnknown(m)
}

var xxx_messageInfo_ThingID proto.InternalMessageInfo

func (m *ThingID) GetValue() uint64 {
	if m != nil {
		return m.Value
	}
	return 0
}

type Token struct {
	Value                string   `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Token) Reset()         { *m = Token{} }
func (m *Token) String() string { return proto.CompactTextString(m) }
func (*Token) ProtoMessage()    {}
func (*Token) Descriptor() ([]byte, []int) {
	return fileDescriptor_internal_50ed0f35f4250621, []int{2}
}
func (m *Token) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Token.Unmarshal(m, b)
}
func (m *Token) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Token.Marshal(b, m, deterministic)
}
func (dst *Token) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Token.Merge(dst, src)
}
func (m *Token) XXX_Size() int {
	return xxx_messageInfo_Token.Size(m)
}
func (m *Token) XXX_DiscardUnknown() {
	xxx_messageInfo_Token.DiscardUnknown(m)
}

var xxx_messageInfo_Token proto.InternalMessageInfo

func (m *Token) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

type UserID struct {
	Value                string   `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *UserID) Reset()         { *m = UserID{} }
func (m *UserID) String() string { return proto.CompactTextString(m) }
func (*UserID) ProtoMessage()    {}
func (*UserID) Descriptor() ([]byte, []int) {
	return fileDescriptor_internal_50ed0f35f4250621, []int{3}
}
func (m *UserID) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UserID.Unmarshal(m, b)
}
func (m *UserID) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UserID.Marshal(b, m, deterministic)
}
func (dst *UserID) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UserID.Merge(dst, src)
}
func (m *UserID) XXX_Size() int {
	return xxx_messageInfo_UserID.Size(m)
}
func (m *UserID) XXX_DiscardUnknown() {
	xxx_messageInfo_UserID.DiscardUnknown(m)
}

var xxx_messageInfo_UserID proto.InternalMessageInfo

func (m *UserID) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

func init() {
	proto.RegisterType((*AccessReq)(nil), "mainflux.AccessReq")
	proto.RegisterType((*ThingID)(nil), "mainflux.ThingID")
	proto.RegisterType((*Token)(nil), "mainflux.Token")
	proto.RegisterType((*UserID)(nil), "mainflux.UserID")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// ThingsServiceClient is the client API for ThingsService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type ThingsServiceClient interface {
	CanAccess(ctx context.Context, in *AccessReq, opts ...grpc.CallOption) (*ThingID, error)
	Identify(ctx context.Context, in *Token, opts ...grpc.CallOption) (*ThingID, error)
}

type thingsServiceClient struct {
	cc *grpc.ClientConn
}

func NewThingsServiceClient(cc *grpc.ClientConn) ThingsServiceClient {
	return &thingsServiceClient{cc}
}

func (c *thingsServiceClient) CanAccess(ctx context.Context, in *AccessReq, opts ...grpc.CallOption) (*ThingID, error) {
	out := new(ThingID)
	err := c.cc.Invoke(ctx, "/mainflux.ThingsService/CanAccess", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *thingsServiceClient) Identify(ctx context.Context, in *Token, opts ...grpc.CallOption) (*ThingID, error) {
	out := new(ThingID)
	err := c.cc.Invoke(ctx, "/mainflux.ThingsService/Identify", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ThingsServiceServer is the server API for ThingsService service.
type ThingsServiceServer interface {
	CanAccess(context.Context, *AccessReq) (*ThingID, error)
	Identify(context.Context, *Token) (*ThingID, error)
}

func RegisterThingsServiceServer(s *grpc.Server, srv ThingsServiceServer) {
	s.RegisterService(&_ThingsService_serviceDesc, srv)
}

func _ThingsService_CanAccess_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AccessReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ThingsServiceServer).CanAccess(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/mainflux.ThingsService/CanAccess",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ThingsServiceServer).CanAccess(ctx, req.(*AccessReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _ThingsService_Identify_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Token)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ThingsServiceServer).Identify(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/mainflux.ThingsService/Identify",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ThingsServiceServer).Identify(ctx, req.(*Token))
	}
	return interceptor(ctx, in, info, handler)
}

var _ThingsService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "mainflux.ThingsService",
	HandlerType: (*ThingsServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CanAccess",
			Handler:    _ThingsService_CanAccess_Handler,
		},
		{
			MethodName: "Identify",
			Handler:    _ThingsService_Identify_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "internal.proto",
}

// UsersServiceClient is the client API for UsersService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type UsersServiceClient interface {
	Identify(ctx context.Context, in *Token, opts ...grpc.CallOption) (*UserID, error)
}

type usersServiceClient struct {
	cc *grpc.ClientConn
}

func NewUsersServiceClient(cc *grpc.ClientConn) UsersServiceClient {
	return &usersServiceClient{cc}
}

func (c *usersServiceClient) Identify(ctx context.Context, in *Token, opts ...grpc.CallOption) (*UserID, error) {
	out := new(UserID)
	err := c.cc.Invoke(ctx, "/mainflux.UsersService/Identify", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UsersServiceServer is the server API for UsersService service.
type UsersServiceServer interface {
	Identify(context.Context, *Token) (*UserID, error)
}

func RegisterUsersServiceServer(s *grpc.Server, srv UsersServiceServer) {
	s.RegisterService(&_UsersService_serviceDesc, srv)
}

func _UsersService_Identify_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Token)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UsersServiceServer).Identify(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/mainflux.UsersService/Identify",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UsersServiceServer).Identify(ctx, req.(*Token))
	}
	return interceptor(ctx, in, info, handler)
}

var _UsersService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "mainflux.UsersService",
	HandlerType: (*UsersServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Identify",
			Handler:    _UsersService_Identify_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "internal.proto",
}

func init() { proto.RegisterFile("internal.proto", fileDescriptor_internal_50ed0f35f4250621) }

var fileDescriptor_internal_50ed0f35f4250621 = []byte{
	// 231 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0xcb, 0xcc, 0x2b, 0x49,
	0x2d, 0xca, 0x4b, 0xcc, 0xd1, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0xc8, 0x4d, 0xcc, 0xcc,
	0x4b, 0xcb, 0x29, 0xad, 0x50, 0xb2, 0xe4, 0xe2, 0x74, 0x4c, 0x4e, 0x4e, 0x2d, 0x2e, 0x0e, 0x4a,
	0x2d, 0x14, 0x12, 0xe1, 0x62, 0x2d, 0xc9, 0xcf, 0x4e, 0xcd, 0x93, 0x60, 0x54, 0x60, 0xd4, 0xe0,
	0x0c, 0x82, 0x70, 0x84, 0xc4, 0xb8, 0xd8, 0x92, 0x33, 0x12, 0xf3, 0x3c, 0x5d, 0x24, 0x98, 0x14,
	0x18, 0x35, 0x58, 0x82, 0xa0, 0x3c, 0x25, 0x79, 0x2e, 0xf6, 0x90, 0x8c, 0xcc, 0xbc, 0x74, 0x4f,
	0x17, 0x90, 0xc6, 0xb2, 0xc4, 0x9c, 0xd2, 0x54, 0xb0, 0x46, 0x96, 0x20, 0x08, 0x47, 0x49, 0x96,
	0x8b, 0x35, 0x04, 0x6c, 0x02, 0x8a, 0x34, 0x27, 0x4c, 0x5a, 0x8e, 0x8b, 0x2d, 0xb4, 0x38, 0xb5,
	0x08, 0x5d, 0x3b, 0x4c, 0xde, 0xa8, 0x82, 0x8b, 0x17, 0x6c, 0x7e, 0x71, 0x70, 0x6a, 0x51, 0x59,
	0x66, 0x72, 0xaa, 0x90, 0x29, 0x17, 0xa7, 0x73, 0x62, 0x1e, 0xc4, 0xb9, 0x42, 0xc2, 0x7a, 0x30,
	0x3f, 0xe8, 0xc1, 0x3d, 0x20, 0x25, 0x88, 0x10, 0x84, 0x3a, 0x4d, 0x89, 0x41, 0xc8, 0x80, 0x8b,
	0xc3, 0x33, 0x25, 0x35, 0xaf, 0x24, 0x33, 0xad, 0x52, 0x88, 0x1f, 0x49, 0x01, 0xc8, 0x69, 0x58,
	0x75, 0x18, 0xd9, 0x73, 0xf1, 0x80, 0x5c, 0x06, 0xb7, 0x58, 0x1f, 0x9f, 0x09, 0x02, 0x08, 0x01,
	0x88, 0x77, 0x94, 0x18, 0x92, 0xd8, 0xc0, 0xc1, 0x6c, 0x0c, 0x08, 0x00, 0x00, 0xff, 0xff, 0x2f,
	0xbc, 0xec, 0x14, 0x78, 0x01, 0x00, 0x00,
}
