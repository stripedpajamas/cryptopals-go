package challenge43

var P []byte = []byte{0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x89, 0xe1, 0x85, 0x52, 0x18, 0xa0, 0xe7, 0xda, 0xc3, 0x81, 0x36, 0xff, 0xaf, 0xa7, 0x2e, 0xda, 0x78, 0x59, 0xf2, 0x17, 0x1e, 0x25, 0xe6, 0x5e, 0xac, 0x69, 0x8c, 0x17, 0x2, 0x57, 0x8b, 0x7, 0xdc, 0x2a, 0x10, 0x76, 0xda, 0x24, 0x1c, 0x76, 0xc6, 0x2d, 0x37, 0x4d, 0x83, 0x89, 0xea, 0x5a, 0xef, 0xfd, 0x32, 0x26, 0xa0, 0x53, 0xc, 0xc5, 0x65, 0xf3, 0xbf, 0x6b, 0x50, 0x92, 0x91, 0x39, 0xeb, 0xea, 0xc0, 0x4f, 0x48, 0xc3, 0xc8, 0x4a, 0xfb, 0x79, 0x6d, 0x61, 0xe5, 0xa4, 0xf9, 0xa8, 0xfd, 0xa8, 0x12, 0xab, 0x59, 0x49, 0x42, 0x32, 0xc7, 0xd2, 0xb4, 0xde, 0xb5, 0xa, 0xa1, 0x8e, 0xe9, 0xe1, 0x32, 0xbf, 0xa8, 0x5a, 0xc4, 0x37, 0x4d, 0x7f, 0x90, 0x91, 0xab, 0xc3, 0xd0, 0x15, 0xef, 0xc8, 0x71, 0xa5, 0x84, 0x47, 0x1b, 0xb1}
var Q []byte = []byte{0xf4, 0xf4, 0x7f, 0x5, 0x79, 0x4b, 0x25, 0x61, 0x74, 0xbb, 0xa6, 0xe9, 0xb3, 0x96, 0xa7, 0x70, 0x7e, 0x56, 0x3c, 0x5b}
var G []byte = []byte{0x59, 0x58, 0xc9, 0xd3, 0x89, 0x8b, 0x22, 0x4b, 0x12, 0x67, 0x2c, 0xb, 0x98, 0xe0, 0x6c, 0x60, 0xdf, 0x92, 0x3c, 0xb8, 0xbc, 0x99, 0x9d, 0x11, 0x94, 0x58, 0xfe, 0xf5, 0x38, 0xb8, 0xfa, 0x40, 0x46, 0xc8, 0xdb, 0x53, 0x3, 0x9d, 0xb6, 0x20, 0xc0, 0x94, 0xc9, 0xfa, 0x7, 0x7e, 0xf3, 0x89, 0xb5, 0x32, 0x2a, 0x55, 0x99, 0x46, 0xa7, 0x19, 0x3, 0xf9, 0x90, 0xf1, 0xf7, 0xe0, 0xe0, 0x25, 0xe2, 0xd7, 0xf7, 0xcf, 0x49, 0x4a, 0xff, 0x1a, 0x4, 0x70, 0xf5, 0xb6, 0x4c, 0x36, 0xb6, 0x25, 0xa0, 0x97, 0xf1, 0x65, 0x1f, 0xe7, 0x75, 0x32, 0x35, 0x56, 0xfe, 0x0, 0xb3, 0x60, 0x8c, 0x88, 0x78, 0x92, 0x87, 0x84, 0x80, 0xe9, 0x90, 0x41, 0xbe, 0x60, 0x1a, 0x62, 0x16, 0x6c, 0xa6, 0x89, 0x4b, 0xdd, 0x41, 0xa7, 0x5, 0x4e, 0xc8, 0x9f, 0x75, 0x6b, 0xa9, 0xfc, 0x95, 0x30, 0x22, 0x91}