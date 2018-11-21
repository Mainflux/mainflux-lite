// Code generated by protoc-gen-go. DO NOT EDIT.
// source: deviceQueue.proto

package api

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import empty "github.com/golang/protobuf/ptypes/empty"
import _ "google.golang.org/genproto/googleapis/api/annotations"

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

type DeviceQueueItem struct {
	// Device EUI (HEX encoded).
	DevEui string `protobuf:"bytes,1,opt,name=dev_eui,json=devEUI,proto3" json:"dev_eui,omitempty"`
	// Set this to true when an acknowledgement from the device is required.
	// Please note that this must not be used to guarantee a delivery.
	Confirmed bool `protobuf:"varint,2,opt,name=confirmed,proto3" json:"confirmed,omitempty"`
	// Downlink frame-counter.
	// This will be automatically set on enquue.
	FCnt uint32 `protobuf:"varint,6,opt,name=f_cnt,json=fCnt,proto3" json:"f_cnt,omitempty"`
	// FPort used (must be > 0)
	FPort uint32 `protobuf:"varint,3,opt,name=f_port,json=fPort,proto3" json:"f_port,omitempty"`
	// Base64 encoded data.
	// Or use the json_object field when an application codec has been configured.
	Data []byte `protobuf:"bytes,4,opt,name=data,proto3" json:"data,omitempty"`
	// JSON object (string).
	// Only use this when an application codec has been configured that can convert
	// this object into binary form.
	JsonObject           string   `protobuf:"bytes,5,opt,name=json_object,json=jsonObject,proto3" json:"json_object,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DeviceQueueItem) Reset()         { *m = DeviceQueueItem{} }
func (m *DeviceQueueItem) String() string { return proto.CompactTextString(m) }
func (*DeviceQueueItem) ProtoMessage()    {}
func (*DeviceQueueItem) Descriptor() ([]byte, []int) {
	return fileDescriptor_ae6ff84951d6e0cf, []int{0}
}
func (m *DeviceQueueItem) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DeviceQueueItem.Unmarshal(m, b)
}
func (m *DeviceQueueItem) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DeviceQueueItem.Marshal(b, m, deterministic)
}
func (dst *DeviceQueueItem) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DeviceQueueItem.Merge(dst, src)
}
func (m *DeviceQueueItem) XXX_Size() int {
	return xxx_messageInfo_DeviceQueueItem.Size(m)
}
func (m *DeviceQueueItem) XXX_DiscardUnknown() {
	xxx_messageInfo_DeviceQueueItem.DiscardUnknown(m)
}

var xxx_messageInfo_DeviceQueueItem proto.InternalMessageInfo

func (m *DeviceQueueItem) GetDevEui() string {
	if m != nil {
		return m.DevEui
	}
	return ""
}

func (m *DeviceQueueItem) GetConfirmed() bool {
	if m != nil {
		return m.Confirmed
	}
	return false
}

func (m *DeviceQueueItem) GetFCnt() uint32 {
	if m != nil {
		return m.FCnt
	}
	return 0
}

func (m *DeviceQueueItem) GetFPort() uint32 {
	if m != nil {
		return m.FPort
	}
	return 0
}

func (m *DeviceQueueItem) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *DeviceQueueItem) GetJsonObject() string {
	if m != nil {
		return m.JsonObject
	}
	return ""
}

type EnqueueDeviceQueueItemRequest struct {
	// Queue-item object to enqueue.
	DeviceQueueItem      *DeviceQueueItem `protobuf:"bytes,1,opt,name=device_queue_item,json=deviceQueueItem,proto3" json:"device_queue_item,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *EnqueueDeviceQueueItemRequest) Reset()         { *m = EnqueueDeviceQueueItemRequest{} }
func (m *EnqueueDeviceQueueItemRequest) String() string { return proto.CompactTextString(m) }
func (*EnqueueDeviceQueueItemRequest) ProtoMessage()    {}
func (*EnqueueDeviceQueueItemRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_ae6ff84951d6e0cf, []int{1}
}
func (m *EnqueueDeviceQueueItemRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EnqueueDeviceQueueItemRequest.Unmarshal(m, b)
}
func (m *EnqueueDeviceQueueItemRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EnqueueDeviceQueueItemRequest.Marshal(b, m, deterministic)
}
func (dst *EnqueueDeviceQueueItemRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EnqueueDeviceQueueItemRequest.Merge(dst, src)
}
func (m *EnqueueDeviceQueueItemRequest) XXX_Size() int {
	return xxx_messageInfo_EnqueueDeviceQueueItemRequest.Size(m)
}
func (m *EnqueueDeviceQueueItemRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_EnqueueDeviceQueueItemRequest.DiscardUnknown(m)
}

var xxx_messageInfo_EnqueueDeviceQueueItemRequest proto.InternalMessageInfo

func (m *EnqueueDeviceQueueItemRequest) GetDeviceQueueItem() *DeviceQueueItem {
	if m != nil {
		return m.DeviceQueueItem
	}
	return nil
}

type EnqueueDeviceQueueItemResponse struct {
	// Frame-counter for the enqueued payload.
	FCnt                 uint32   `protobuf:"varint,1,opt,name=f_cnt,json=fCnt,proto3" json:"f_cnt,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *EnqueueDeviceQueueItemResponse) Reset()         { *m = EnqueueDeviceQueueItemResponse{} }
func (m *EnqueueDeviceQueueItemResponse) String() string { return proto.CompactTextString(m) }
func (*EnqueueDeviceQueueItemResponse) ProtoMessage()    {}
func (*EnqueueDeviceQueueItemResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_ae6ff84951d6e0cf, []int{2}
}
func (m *EnqueueDeviceQueueItemResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EnqueueDeviceQueueItemResponse.Unmarshal(m, b)
}
func (m *EnqueueDeviceQueueItemResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EnqueueDeviceQueueItemResponse.Marshal(b, m, deterministic)
}
func (dst *EnqueueDeviceQueueItemResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EnqueueDeviceQueueItemResponse.Merge(dst, src)
}
func (m *EnqueueDeviceQueueItemResponse) XXX_Size() int {
	return xxx_messageInfo_EnqueueDeviceQueueItemResponse.Size(m)
}
func (m *EnqueueDeviceQueueItemResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_EnqueueDeviceQueueItemResponse.DiscardUnknown(m)
}

var xxx_messageInfo_EnqueueDeviceQueueItemResponse proto.InternalMessageInfo

func (m *EnqueueDeviceQueueItemResponse) GetFCnt() uint32 {
	if m != nil {
		return m.FCnt
	}
	return 0
}

type FlushDeviceQueueRequest struct {
	// Device EUI (HEX encoded).
	DevEui               string   `protobuf:"bytes,1,opt,name=dev_eui,json=devEUI,proto3" json:"dev_eui,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FlushDeviceQueueRequest) Reset()         { *m = FlushDeviceQueueRequest{} }
func (m *FlushDeviceQueueRequest) String() string { return proto.CompactTextString(m) }
func (*FlushDeviceQueueRequest) ProtoMessage()    {}
func (*FlushDeviceQueueRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_ae6ff84951d6e0cf, []int{3}
}
func (m *FlushDeviceQueueRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FlushDeviceQueueRequest.Unmarshal(m, b)
}
func (m *FlushDeviceQueueRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FlushDeviceQueueRequest.Marshal(b, m, deterministic)
}
func (dst *FlushDeviceQueueRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FlushDeviceQueueRequest.Merge(dst, src)
}
func (m *FlushDeviceQueueRequest) XXX_Size() int {
	return xxx_messageInfo_FlushDeviceQueueRequest.Size(m)
}
func (m *FlushDeviceQueueRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_FlushDeviceQueueRequest.DiscardUnknown(m)
}

var xxx_messageInfo_FlushDeviceQueueRequest proto.InternalMessageInfo

func (m *FlushDeviceQueueRequest) GetDevEui() string {
	if m != nil {
		return m.DevEui
	}
	return ""
}

type ListDeviceQueueItemsRequest struct {
	// Device EUI (HEX encoded).
	DevEui               string   `protobuf:"bytes,1,opt,name=dev_eui,json=devEUI,proto3" json:"dev_eui,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ListDeviceQueueItemsRequest) Reset()         { *m = ListDeviceQueueItemsRequest{} }
func (m *ListDeviceQueueItemsRequest) String() string { return proto.CompactTextString(m) }
func (*ListDeviceQueueItemsRequest) ProtoMessage()    {}
func (*ListDeviceQueueItemsRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_ae6ff84951d6e0cf, []int{4}
}
func (m *ListDeviceQueueItemsRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListDeviceQueueItemsRequest.Unmarshal(m, b)
}
func (m *ListDeviceQueueItemsRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListDeviceQueueItemsRequest.Marshal(b, m, deterministic)
}
func (dst *ListDeviceQueueItemsRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListDeviceQueueItemsRequest.Merge(dst, src)
}
func (m *ListDeviceQueueItemsRequest) XXX_Size() int {
	return xxx_messageInfo_ListDeviceQueueItemsRequest.Size(m)
}
func (m *ListDeviceQueueItemsRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ListDeviceQueueItemsRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ListDeviceQueueItemsRequest proto.InternalMessageInfo

func (m *ListDeviceQueueItemsRequest) GetDevEui() string {
	if m != nil {
		return m.DevEui
	}
	return ""
}

type ListDeviceQueueItemsResponse struct {
	DeviceQueueItems     []*DeviceQueueItem `protobuf:"bytes,1,rep,name=device_queue_items,json=deviceQueueItems,proto3" json:"device_queue_items,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *ListDeviceQueueItemsResponse) Reset()         { *m = ListDeviceQueueItemsResponse{} }
func (m *ListDeviceQueueItemsResponse) String() string { return proto.CompactTextString(m) }
func (*ListDeviceQueueItemsResponse) ProtoMessage()    {}
func (*ListDeviceQueueItemsResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_ae6ff84951d6e0cf, []int{5}
}
func (m *ListDeviceQueueItemsResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListDeviceQueueItemsResponse.Unmarshal(m, b)
}
func (m *ListDeviceQueueItemsResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListDeviceQueueItemsResponse.Marshal(b, m, deterministic)
}
func (dst *ListDeviceQueueItemsResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListDeviceQueueItemsResponse.Merge(dst, src)
}
func (m *ListDeviceQueueItemsResponse) XXX_Size() int {
	return xxx_messageInfo_ListDeviceQueueItemsResponse.Size(m)
}
func (m *ListDeviceQueueItemsResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ListDeviceQueueItemsResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ListDeviceQueueItemsResponse proto.InternalMessageInfo

func (m *ListDeviceQueueItemsResponse) GetDeviceQueueItems() []*DeviceQueueItem {
	if m != nil {
		return m.DeviceQueueItems
	}
	return nil
}

func init() {
	proto.RegisterType((*DeviceQueueItem)(nil), "api.DeviceQueueItem")
	proto.RegisterType((*EnqueueDeviceQueueItemRequest)(nil), "api.EnqueueDeviceQueueItemRequest")
	proto.RegisterType((*EnqueueDeviceQueueItemResponse)(nil), "api.EnqueueDeviceQueueItemResponse")
	proto.RegisterType((*FlushDeviceQueueRequest)(nil), "api.FlushDeviceQueueRequest")
	proto.RegisterType((*ListDeviceQueueItemsRequest)(nil), "api.ListDeviceQueueItemsRequest")
	proto.RegisterType((*ListDeviceQueueItemsResponse)(nil), "api.ListDeviceQueueItemsResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// DeviceQueueServiceClient is the client API for DeviceQueueService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type DeviceQueueServiceClient interface {
	// Enqueue adds the given item to the device-queue.
	Enqueue(ctx context.Context, in *EnqueueDeviceQueueItemRequest, opts ...grpc.CallOption) (*EnqueueDeviceQueueItemResponse, error)
	// Flush flushes the downlink device-queue.
	Flush(ctx context.Context, in *FlushDeviceQueueRequest, opts ...grpc.CallOption) (*empty.Empty, error)
	// List lists the items in the device-queue.
	List(ctx context.Context, in *ListDeviceQueueItemsRequest, opts ...grpc.CallOption) (*ListDeviceQueueItemsResponse, error)
}

type deviceQueueServiceClient struct {
	cc *grpc.ClientConn
}

func NewDeviceQueueServiceClient(cc *grpc.ClientConn) DeviceQueueServiceClient {
	return &deviceQueueServiceClient{cc}
}

func (c *deviceQueueServiceClient) Enqueue(ctx context.Context, in *EnqueueDeviceQueueItemRequest, opts ...grpc.CallOption) (*EnqueueDeviceQueueItemResponse, error) {
	out := new(EnqueueDeviceQueueItemResponse)
	err := c.cc.Invoke(ctx, "/api.DeviceQueueService/Enqueue", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *deviceQueueServiceClient) Flush(ctx context.Context, in *FlushDeviceQueueRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/api.DeviceQueueService/Flush", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *deviceQueueServiceClient) List(ctx context.Context, in *ListDeviceQueueItemsRequest, opts ...grpc.CallOption) (*ListDeviceQueueItemsResponse, error) {
	out := new(ListDeviceQueueItemsResponse)
	err := c.cc.Invoke(ctx, "/api.DeviceQueueService/List", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeviceQueueServiceServer is the server API for DeviceQueueService service.
type DeviceQueueServiceServer interface {
	// Enqueue adds the given item to the device-queue.
	Enqueue(context.Context, *EnqueueDeviceQueueItemRequest) (*EnqueueDeviceQueueItemResponse, error)
	// Flush flushes the downlink device-queue.
	Flush(context.Context, *FlushDeviceQueueRequest) (*empty.Empty, error)
	// List lists the items in the device-queue.
	List(context.Context, *ListDeviceQueueItemsRequest) (*ListDeviceQueueItemsResponse, error)
}

func RegisterDeviceQueueServiceServer(s *grpc.Server, srv DeviceQueueServiceServer) {
	s.RegisterService(&_DeviceQueueService_serviceDesc, srv)
}

func _DeviceQueueService_Enqueue_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EnqueueDeviceQueueItemRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DeviceQueueServiceServer).Enqueue(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.DeviceQueueService/Enqueue",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DeviceQueueServiceServer).Enqueue(ctx, req.(*EnqueueDeviceQueueItemRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _DeviceQueueService_Flush_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FlushDeviceQueueRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DeviceQueueServiceServer).Flush(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.DeviceQueueService/Flush",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DeviceQueueServiceServer).Flush(ctx, req.(*FlushDeviceQueueRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _DeviceQueueService_List_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListDeviceQueueItemsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DeviceQueueServiceServer).List(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.DeviceQueueService/List",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DeviceQueueServiceServer).List(ctx, req.(*ListDeviceQueueItemsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _DeviceQueueService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "api.DeviceQueueService",
	HandlerType: (*DeviceQueueServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Enqueue",
			Handler:    _DeviceQueueService_Enqueue_Handler,
		},
		{
			MethodName: "Flush",
			Handler:    _DeviceQueueService_Flush_Handler,
		},
		{
			MethodName: "List",
			Handler:    _DeviceQueueService_List_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "deviceQueue.proto",
}

func init() { proto.RegisterFile("deviceQueue.proto", fileDescriptor_ae6ff84951d6e0cf) }

var fileDescriptor_ae6ff84951d6e0cf = []byte{
	// 462 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x53, 0xcd, 0x6e, 0xd3, 0x40,
	0x10, 0xd6, 0xe6, 0xaf, 0x74, 0x0a, 0x2a, 0x0c, 0x3f, 0xb5, 0x5c, 0x53, 0x8c, 0xe1, 0x10, 0xf5,
	0x60, 0x4b, 0xa9, 0x40, 0x82, 0x13, 0x02, 0x82, 0x54, 0x09, 0x09, 0x30, 0xe2, 0x6c, 0x39, 0xf6,
	0xb8, 0x6c, 0x95, 0xec, 0x3a, 0xde, 0x75, 0x24, 0x84, 0xb8, 0x70, 0xe7, 0xc4, 0x53, 0xf0, 0x3c,
	0xbc, 0x02, 0x8f, 0xc1, 0x01, 0x79, 0xed, 0x28, 0x21, 0x21, 0xe6, 0xb6, 0xfe, 0x76, 0x66, 0xbf,
	0x9f, 0xf1, 0xc0, 0x8d, 0x94, 0x16, 0x3c, 0xa1, 0x77, 0x25, 0x95, 0xe4, 0xe7, 0x85, 0xd4, 0x12,
	0xbb, 0x71, 0xce, 0x6d, 0xe7, 0x42, 0xca, 0x8b, 0x29, 0x05, 0x71, 0xce, 0x83, 0x58, 0x08, 0xa9,
	0x63, 0xcd, 0xa5, 0x50, 0x75, 0x89, 0x7d, 0xdc, 0xdc, 0x9a, 0xaf, 0x49, 0x99, 0x05, 0x34, 0xcb,
	0xf5, 0xa7, 0xfa, 0xd2, 0xfb, 0xc1, 0xe0, 0xf0, 0xe5, 0xea, 0xd5, 0x73, 0x4d, 0x33, 0x3c, 0x82,
	0xbd, 0x94, 0x16, 0x11, 0x95, 0xdc, 0x62, 0x2e, 0x1b, 0xee, 0x87, 0x83, 0x94, 0x16, 0xe3, 0x0f,
	0xe7, 0xe8, 0xc0, 0x7e, 0x22, 0x45, 0xc6, 0x8b, 0x19, 0xa5, 0x56, 0xc7, 0x65, 0xc3, 0x2b, 0xe1,
	0x0a, 0xc0, 0x9b, 0xd0, 0xcf, 0xa2, 0x44, 0x68, 0x6b, 0xe0, 0xb2, 0xe1, 0xb5, 0xb0, 0x97, 0xbd,
	0x10, 0x1a, 0x6f, 0xc3, 0x20, 0x8b, 0x72, 0x59, 0x68, 0xab, 0x6b, 0xd0, 0x7e, 0xf6, 0x56, 0x16,
	0x1a, 0x11, 0x7a, 0x69, 0xac, 0x63, 0xab, 0xe7, 0xb2, 0xe1, 0xd5, 0xd0, 0x9c, 0xf1, 0x1e, 0x1c,
	0x5c, 0x2a, 0x29, 0x22, 0x39, 0xb9, 0xa4, 0x44, 0x5b, 0x7d, 0x43, 0x0d, 0x15, 0xf4, 0xc6, 0x20,
	0x5e, 0x0c, 0x77, 0xc7, 0x62, 0x5e, 0xc9, 0xdc, 0x50, 0x1c, 0xd2, 0xbc, 0x24, 0xa5, 0xf1, 0xd9,
	0x32, 0xa1, 0xc8, 0x54, 0x45, 0x5c, 0xd3, 0xcc, 0x58, 0x38, 0x18, 0xdd, 0xf2, 0xe3, 0x9c, 0xfb,
	0x9b, 0x7d, 0x87, 0xe9, 0xdf, 0x80, 0xf7, 0x08, 0x4e, 0x76, 0x51, 0xa8, 0x5c, 0x0a, 0x45, 0x2b,
	0x97, 0x6c, 0xe5, 0xd2, 0x1b, 0xc1, 0xd1, 0xab, 0x69, 0xa9, 0x3e, 0xae, 0x35, 0x2d, 0x35, 0xed,
	0x0a, 0xd3, 0x7b, 0x0c, 0xc7, 0xaf, 0xb9, 0xd2, 0x1b, 0x3c, 0xea, 0xbf, 0x7d, 0x13, 0x70, 0xfe,
	0xdd, 0xd7, 0x08, 0x7c, 0x0e, 0xb8, 0x15, 0x82, 0xb2, 0x98, 0xdb, 0xdd, 0x99, 0xc2, 0xf5, 0x8d,
	0x14, 0xd4, 0xe8, 0x77, 0x07, 0x70, 0xad, 0xea, 0x3d, 0x15, 0xd5, 0x19, 0xbf, 0x31, 0xd8, 0x6b,
	0xe2, 0x41, 0xcf, 0x3c, 0xd5, 0x3a, 0x0f, 0xfb, 0x41, 0x6b, 0x4d, 0xad, 0xd7, 0x7b, 0xf2, 0xf5,
	0xe7, 0xaf, 0xef, 0x9d, 0x33, 0xcf, 0x37, 0xbf, 0x6f, 0x2d, 0x45, 0x05, 0x9f, 0xb7, 0x3c, 0xf8,
	0x4d, 0x1c, 0x5f, 0x02, 0x83, 0x3d, 0x65, 0xa7, 0x98, 0x40, 0xdf, 0xc4, 0x8e, 0x8e, 0x21, 0xda,
	0x31, 0x02, 0xfb, 0x8e, 0x5f, 0x6f, 0x80, 0xbf, 0xdc, 0x00, 0x7f, 0x5c, 0x6d, 0x80, 0xf7, 0xd0,
	0x30, 0x9f, 0x9c, 0x3a, 0x5b, 0xcc, 0x6b, 0x3c, 0x38, 0x87, 0x5e, 0x95, 0x37, 0xba, 0x86, 0xa3,
	0x65, 0x64, 0xf6, 0xfd, 0x96, 0x8a, 0xc6, 0x6c, 0x43, 0x89, 0xad, 0x94, 0x93, 0x81, 0x11, 0x7a,
	0xf6, 0x27, 0x00, 0x00, 0xff, 0xff, 0x2e, 0x6a, 0x2a, 0x84, 0xf0, 0x03, 0x00, 0x00,
}
