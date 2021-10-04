// Code generated for package noauth by go-bindata DO NOT EDIT. (@generated)
// sources:
// 01_base_schema.graphql
// 02_unauth_schema.graphql
// 03_auth_schema.graphql
package noauth

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

// Name return file name
func (fi bindataFileInfo) Name() string {
	return fi.name
}

// Size return file size
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}

// Mode return file mode
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}

// Mode return file modify time
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}

// IsDir return file whether a directory
func (fi bindataFileInfo) IsDir() bool {
	return fi.mode&os.ModeDir != 0
}

// Sys return file is sys mode
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var __01_base_schemaGraphql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x6c\x8f\xb1\x4e\xc4\x30\x10\x44\x7b\x7f\xc5\xa0\x14\x54\x5c\x2a\x10\x4a\x49\x4f\x81\xe0\x07\x1c\x7b\x38\x47\x72\xbc\x3e\xef\x46\x47\x84\xf8\x77\x94\xcb\x5d\x77\xd5\x6c\x31\xf3\xb4\x4f\x43\xe2\xec\xf1\xeb\x80\xd3\xc2\xb6\x0e\xf8\xd8\xc2\x01\xf3\x62\xde\x26\x29\x03\xde\xaf\x97\xfb\x73\xae\xc3\x57\x22\xb4\x32\x20\x0a\xb5\x3c\x1a\x7c\xce\x72\x06\xe7\x6a\x2b\x6c\xad\xd4\x83\xeb\xf0\x29\x38\x13\xa1\xd1\x1b\x51\x7d\x0e\x4c\x92\x23\x9b\x22\xb1\x11\xbe\xc4\xeb\xce\x12\x95\xfb\x0e\x26\x18\xe9\x3a\xf0\xc7\x58\x22\x23\xc6\x15\x62\x89\x0d\xdf\x53\xde\xb9\xc9\xac\xea\xd0\xf7\xc7\xc9\xd2\x32\x1e\x82\xcc\xfd\xb1\xf9\x9a\x4e\xf9\x96\x4f\xdb\x73\xfd\xa4\xba\x50\xfb\xe7\x97\x57\xe7\x36\xf8\xae\x75\xf1\x2c\x22\x75\xc0\x9b\x48\xa6\x2f\x0f\x9b\xd4\xa5\x70\xb3\xbc\xdf\xf9\x0f\x00\x00\xff\xff\x6f\xc4\xb8\xef\x28\x01\x00\x00")

func _01_base_schemaGraphqlBytes() ([]byte, error) {
	return bindataRead(
		__01_base_schemaGraphql,
		"01_base_schema.graphql",
	)
}

func _01_base_schemaGraphql() (*asset, error) {
	bytes, err := _01_base_schemaGraphqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "01_base_schema.graphql", size: 296, mode: os.FileMode(436), modTime: time.Unix(1, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var __02_unauth_schemaGraphql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x64\x8d\x31\x0a\x02\x31\x10\x45\xfb\x9c\xe2\x6f\xa7\x57\x48\x67\x23\x58\x28\x88\xa5\x58\x0c\xeb\x6c\x0c\x6c\x26\x4b\x66\x14\x17\xf1\xee\x62\x20\xa2\xd8\x0d\x6f\x1e\xef\xf3\xdd\x58\xce\xb0\x79\x62\xec\xaf\x5c\x66\x3c\x1c\x40\xc5\xe2\x40\xbd\xe9\xa2\x5d\x3b\x4a\xec\x71\xb0\x12\x25\x74\x4b\x8f\x55\x33\x36\x32\xe4\xce\x3d\x9d\xab\x89\x1f\x5c\x53\xd1\x38\xa9\xc7\xb1\x7d\xba\xd3\xbf\x5d\xc5\x1b\x17\x8d\x59\x3e\x23\x0e\xe8\x2f\x24\x81\xc7\x1c\xbe\xa1\xc5\xc4\x6a\x94\xa6\xad\x7a\xac\xc7\x4c\xf6\x0e\xbe\x02\x00\x00\xff\xff\xa4\xc1\x10\x47\xc8\x00\x00\x00")

func _02_unauth_schemaGraphqlBytes() ([]byte, error) {
	return bindataRead(
		__02_unauth_schemaGraphql,
		"02_unauth_schema.graphql",
	)
}

func _02_unauth_schemaGraphql() (*asset, error) {
	bytes, err := _02_unauth_schemaGraphqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "02_unauth_schema.graphql", size: 200, mode: os.FileMode(436), modTime: time.Unix(1, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var __03_auth_schemaGraphql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x59\xdd\x6f\xe3\xb8\x11\x7f\xf7\x5f\x31\x7b\xfb\x70\x09\x10\x2c\x0e\x45\xef\x50\xf8\xa9\x3a\x5b\x7b\xab\x26\x71\xdc\xd8\xd9\xed\xa1\x58\x2c\x68\x69\x6c\x11\x91\x49\x1d\x39\x72\xe2\x16\xfb\xbf\x17\x43\x52\x1f\xb4\x95\xdb\xe6\xda\x37\x8b\x1f\x33\xbf\xf9\xe0\x8f\x33\x34\x3e\x13\xaa\x02\xe8\x58\x23\xfc\xbd\x41\x73\x84\x7f\x4f\x00\x1a\x8b\x66\x0a\x0f\x16\x4d\xa6\xb6\xfa\xcd\x04\x40\x9b\xdd\x14\xee\xcc\xae\xfd\xe6\x15\x2b\x24\x92\x6a\x67\xfd\xca\xf6\xab\x9d\x4d\x88\x8c\xdc\x34\x84\x61\xbe\xff\x0e\xf2\x78\xd0\x4e\xe1\x9f\x9d\x9a\xcf\x3c\x91\x57\x8d\x25\x34\x17\xb2\x98\x42\x36\x7f\x73\x39\x85\x99\x1f\x69\x35\x87\x05\x3f\x1f\x17\x62\x8f\x17\x4a\xec\x71\x0a\x2b\x32\x52\xed\x5e\x5e\xcc\x6a\x86\x33\x43\x4d\x33\xad\x14\xe6\x24\xb5\x3a\xd7\xd9\xcf\xf5\x02\x65\x62\x48\x6e\x45\x4e\x17\x22\xfc\x58\x1f\x6b\x9c\x42\x32\xf8\x72\x22\x6e\xb2\x76\x88\x37\x8a\x86\x74\xae\xf7\x75\x85\x84\x17\x52\xd5\x0d\xb5\xb0\xaf\x20\x6f\x8c\xd5\x66\xa9\xed\x14\x32\x45\x57\x20\x9c\xca\x29\x24\x83\x3d\x89\x1b\x63\xe1\x57\x2d\xf2\x87\x6c\xde\xca\xb8\x8c\x17\xdf\xa3\x6d\xaa\x33\xb5\xef\x25\x56\xc5\xa9\xee\x2d\x0f\x06\x0b\x06\x6b\x53\x45\x92\x8e\xd7\x52\x15\x57\x13\x00\x00\x83\xbf\x35\xd2\x60\x91\x98\x1d\x2f\x66\x87\x8e\x2f\xff\xfc\x02\xbc\x68\xf9\xaa\xd9\xed\xd0\xb2\x41\x9f\x27\x13\x80\xb7\xb0\xca\x8d\xac\x69\xbf\x33\x80\xaa\xa8\xb5\x54\x64\xaf\xc0\xe0\x16\x0d\x90\x86\x42\xe7\x16\xa4\x82\xbc\xd2\x4d\x21\x6a\xf9\xae\x36\x9a\xf4\x04\xa0\x92\x07\xfc\x28\xf1\x89\xe1\xdc\x84\xdf\xb7\x48\xa2\x10\x24\x7c\x90\xdb\x15\x33\xad\x08\x15\xd9\x41\x8c\x6f\x4e\xa6\x78\xb9\x75\x38\x58\x9c\x47\x14\x0b\xf3\xb3\x23\xa2\x56\xd1\xc4\x1b\x6f\xd3\x1c\xeb\x4a\x1f\xe1\x11\x8f\x76\x02\x50\xb8\xaf\x3d\x2a\xba\xc6\x23\x2b\x98\x0f\x07\x62\x3d\xd1\xda\x81\x9a\x68\x4b\xd0\x92\x2c\xb3\x56\x85\xa8\x65\x90\x9d\x2c\xb3\x33\xa1\x7e\x76\x20\xcd\x2f\x7a\x33\xf9\x3a\x99\x0c\x59\xe0\xb6\x21\xc1\x91\x71\x44\x30\x33\x28\x08\xc3\x69\x88\x4e\x17\xfc\xb5\xc0\xda\x60\x2e\x08\x8b\x0b\x83\xc2\x72\xc2\x7e\x17\x16\x58\x10\x06\x41\xe9\x27\xc8\x9d\x80\x02\x0e\x52\x40\xfd\x1c\x2c\xfb\xee\x72\x02\xf0\x50\x17\x82\xf0\xa3\xfc\x97\x74\xe7\x6c\x2b\x77\x17\x21\x71\x38\x6f\xb2\xf9\x9b\x2b\x38\x0c\x26\xa7\x90\x16\x92\xc4\xa6\x8a\xb6\x8c\x1c\x79\x0f\x39\x72\xd5\x99\xe7\x00\xe6\xc8\x79\x38\x7f\xc1\xd1\x3f\x6b\x5d\xa1\x50\xbd\x38\xef\xab\xde\x67\xad\x00\xff\x3d\xbe\xd3\x1b\x38\xa4\xc6\x0b\xdb\x31\x66\x6b\x4c\xc4\x9c\x97\xe7\x4c\xba\x42\x8a\xc9\xf3\x42\x0c\x78\x75\x28\x65\xc0\xaf\x97\x63\x8c\x9b\xa9\x83\xf4\x70\x2e\x70\x2f\x64\xd5\xb1\x26\x73\x80\xb1\xb4\x18\x32\xe9\x15\x54\xe2\x64\xe8\xb2\xbd\x10\x58\x4c\x6c\xdf\x12\xcd\x5e\x5a\x2b\xb5\xb2\x17\x4c\xfd\x5d\x00\x9b\x78\x32\x06\x3c\x98\xe8\x85\xfb\x18\x7a\xd1\x77\x66\xd7\x79\x4e\x9b\x5d\x27\x55\xf7\xe3\xbd\xc4\xc1\x62\x96\xd6\x5d\x55\x5f\x27\x13\x97\xd6\xad\x78\x97\xd6\x21\x5e\x13\x80\xe8\xfe\x98\x00\xc4\xae\x99\x00\xd4\x32\xa7\xc6\x44\x6b\xb4\xd9\x2d\x4e\xb6\x05\x78\xfd\x80\xb4\x49\x5d\x1b\x7d\xc0\x62\x90\x13\x2d\x96\x6c\x9e\x2e\x05\x95\x0e\x4a\x36\x4f\x4f\x85\xd5\x82\xca\xfe\xbb\xdd\x14\x2c\xfa\x16\x7e\xc5\xce\xf0\xba\x45\x65\xa3\x84\x94\x05\xb2\x5a\x26\x88\x80\x80\x99\x61\xe8\xa0\xd6\x83\x4e\x89\x50\xa2\x3a\x92\xcc\xed\x5d\x4d\x9a\xaf\x8c\x48\x94\x07\x30\xdc\xdc\xa7\x9b\xdb\x4e\xba\x31\x2b\x44\xf5\xd2\x3e\x77\x0f\xbd\x90\xc1\xe3\x02\xc6\x77\xfd\x57\x98\x3b\xa0\x31\x33\x9e\x38\x33\x90\x55\x42\xb7\x76\x0a\xef\x2b\x2d\xc8\xb3\xb1\xcd\xcf\xc3\xe1\x05\x9d\x08\x78\x64\x8e\xe8\x83\xf1\x1a\x79\xa3\xd7\xc1\xff\x80\x2f\x92\xf7\x7f\x81\x89\xaa\xd9\x8f\xd4\x08\x2b\x12\x84\x4e\x41\x92\xae\xbe\x3c\x2c\xae\x17\x77\x9f\x16\xe1\x6b\x99\x2e\xe6\xd9\xe2\x97\xf0\x75\xff\xb0\x58\xf4\x5f\xef\x93\xec\x26\x9d\x87\x8f\x75\x7a\x7f\x9b\x2d\x92\x75\x3a\x1f\xd5\xd4\x17\x3f\x5e\x51\xb2\x1e\x28\x7a\x0b\x89\x02\x2c\x24\x85\xba\x09\x74\xce\x05\x15\xc8\x2d\x08\xc7\x40\x50\x0a\x0b\x7b\x5d\xc8\xad\xc4\x02\xa8\x44\xf0\x59\x44\xf8\x4c\xb0\x39\x82\x54\x16\x0d\xe7\x10\x68\x03\x05\xf3\x3a\xff\xce\x4b\x61\x44\xce\x97\xd9\x3b\xa7\x64\x5d\x4a\x2e\x42\xf2\xaa\x29\xd0\xf2\x55\xe9\x36\x28\x27\xef\x11\x8f\x1b\x2d\x4c\x01\x42\x15\x50\x0b\xeb\x05\xe8\xfd\x5e\xa8\xc2\x6d\x67\xc4\xe9\x3c\x5b\x7b\xb8\x60\xb1\xc2\xbc\xc7\xab\xaa\xe3\x38\xe8\xbc\xd4\x16\x15\x08\x15\xd5\x71\x60\xbb\xf2\xe9\x5d\x0b\xab\x90\x7c\x13\x5b\x70\x65\xd1\x5b\x07\x2a\xda\x42\xa5\x20\x90\x04\xb6\xd4\x4d\x55\xc0\x5e\x1f\xd0\x2d\x62\x55\xdf\xdb\x50\x81\x72\xad\xc5\x83\x8a\x1d\x23\x98\x43\x6a\x23\x39\xba\x24\x36\xad\x15\xab\xf4\x26\x9d\xad\x7f\x27\x1f\xb8\x08\x0c\xe9\x70\x1d\xa5\xc3\xf5\x97\xe5\xdd\x3c\xfc\x5a\x7d\x9c\xb5\xbf\x66\xf7\xd9\x72\x1d\x3e\x16\xc9\x6d\xba\x5a\x26\xb3\xb4\x3f\x66\xa3\x55\xa3\x93\xff\x28\x55\xf1\x52\xd1\x7a\xc2\x8c\x21\x9d\xb9\x48\x73\x85\x75\x37\xba\x17\x94\x97\x58\x64\xaa\xc0\x67\x57\xd4\x66\x8a\x3e\x73\xa5\xc7\x49\x3d\x26\xdc\x65\x7b\x87\x6e\x2d\x36\x27\xa0\x38\x4f\x38\xbf\x0a\x7c\x06\xbd\x75\xde\x24\xb1\xf1\xee\xa7\x12\xed\x30\x78\xbe\x4a\xda\x6a\xc3\xbe\x25\xb1\x71\x28\x5c\x0b\xe0\x04\x7d\x2a\x91\x4a\x34\x21\x59\x38\xa3\xc4\x60\x33\xef\x03\xe2\xe0\xb3\x7c\xaf\xf0\x49\x56\x15\xec\xc5\xa3\x0f\x6d\xc8\x3f\xc0\x67\xcc\x1b\x47\x97\xac\xa7\xff\x4a\xb6\xc4\xec\xc9\xc2\x7b\x9e\x84\x21\xbe\xdf\xa9\xda\xc7\xe2\xe3\xbb\x8e\x81\x1b\xb6\xda\xec\x05\x71\xf9\xe7\x0f\x1c\x83\xed\x4e\x9f\x0d\x0d\xc8\x53\x29\xf3\xd2\x65\xfb\x06\x51\x41\x2d\x8c\xc5\x82\x8f\xe5\x79\x0e\xeb\x2e\xd1\x7d\x92\x8b\xcd\x8a\x74\x0d\xb5\xb6\xd2\xe1\x65\xfb\x3a\x9d\xd9\xb0\xcf\x89\x1c\x7a\x8a\x81\x71\x09\x38\x88\x4a\x16\x57\x03\xff\xb4\x0e\x7c\xe7\xae\xf3\xb4\x1b\x1f\x3a\xeb\x2d\x24\x55\x15\x85\x94\xc3\x82\x22\x2f\x07\xd1\x67\x90\x36\xc4\x78\x15\x79\x37\xca\x9f\xde\xa9\xdc\x48\x08\xa9\xd0\x70\xb6\x35\xfe\x66\x3b\xbd\xe8\xc7\x49\x3b\xe4\x6d\xbf\x6c\x8f\xd6\x8a\x5d\x34\xd4\x16\xeb\xc3\x11\x4b\xc2\xd0\x4c\x37\x8a\x5c\xfe\xf5\xd7\xc8\xf5\x5f\x6c\x7a\x40\xe5\xa3\x3a\x22\xcc\x95\x8e\x6b\xb9\xc7\x08\x06\x17\x8f\x27\x83\xad\xc0\xa5\x2e\xfe\x90\x55\x8d\x7d\xb5\x59\x79\xeb\x46\xd7\xfe\xc7\x3e\xf5\x3d\x11\xb2\x69\x3c\xdb\x9a\xe9\x87\xc7\xfd\xe1\xf8\x2e\x34\x1b\x03\x13\x7c\xaa\x17\xb8\x15\x9c\xfc\x2e\x00\xcc\xe2\x4a\x53\x19\x72\xeb\x51\xe9\x27\xc5\xf1\x9f\xad\xa2\x6b\x8b\xf7\x85\xf5\x16\x4a\x14\x15\x95\x47\xde\x5a\xa2\x30\xb4\x41\x41\x9e\x20\x0c\xe6\x28\x0f\x58\xf0\x65\x63\x70\xd7\x54\xc2\x80\x54\x84\x86\x0b\x3c\x77\xe3\x50\xe9\x0f\x44\xe8\x9f\x58\x9c\x41\x5b\x6b\x55\x30\x02\xd2\xae\x7b\x47\x4b\x36\x80\xf8\x90\x26\x37\xeb\x0f\xbf\x9e\x83\x68\xd4\x00\x86\xe3\x90\x5e\x62\xee\xdf\x42\xf8\x06\xd5\xb0\x94\xcf\x12\x61\xc6\xfd\xb8\x43\x20\x2d\x70\xc5\x29\x8b\xf6\xac\xf5\x36\x5c\xc1\xc6\x1d\x7d\xf5\x3d\xc1\x6f\x0d\x9a\xa3\x3b\x5b\x7c\x4c\xac\xde\x63\x08\x5b\xb8\xc7\x0c\x5a\xdc\x6f\x2a\xb4\xf0\x61\xbd\x5e\x7e\x6f\xe1\xc7\x1f\x7e\x08\xd1\xef\xfc\x37\x0e\xde\x51\xdf\x4e\xbb\xd7\x02\x69\x7b\xac\xc1\x8e\x5f\xee\x97\xb3\xd6\x02\x26\xcf\x8d\x41\xf1\x68\xdf\x39\x01\xa5\xae\xd1\x53\x93\xa0\xee\xf2\x6c\x0d\x77\x72\x73\x06\xba\x11\xf9\x23\x5f\xd5\x52\xa1\x33\xd9\xa0\x6d\xf6\x4c\x24\x10\x10\x79\x24\x01\xe7\x3c\x5b\xcd\xee\x16\x8b\x74\xb6\x76\x35\xce\xa9\x9f\xb9\xbf\xe1\xd8\x3c\x95\xa8\x4e\x1d\x2d\xfd\x48\x6d\x74\x8e\xd6\x32\x8f\xb4\xcb\x5b\x1f\x2c\xe7\xc9\xda\x17\x52\x5e\xae\xef\x93\x7d\xc5\xd0\x5a\xee\xdd\xce\x43\x4a\x13\x58\x3e\xc2\x42\x1d\x41\x3b\x06\xdc\x36\xc6\x5f\x2d\x3e\x8d\x9d\x7c\xb4\x20\x36\xba\xf1\x2e\x78\x0a\x54\x29\x69\x98\x9b\xda\x9c\x42\x39\xb7\x31\x60\x79\x12\x16\xc8\x1c\x43\xfe\x79\x05\x1e\xd2\x56\xc8\x0a\xbb\xac\x51\xfa\x89\x0d\x16\xb0\x11\x45\xe4\x40\x67\x64\xda\x56\x89\x2d\x7b\x0c\x7b\x7f\x77\xfa\x6a\x61\x2d\x95\x46\x37\xbb\x32\x75\xad\xcf\x58\xbf\x35\x7c\xb6\x88\x2b\xe1\x96\x59\xa2\x63\xdd\x32\xd8\x87\x36\x87\x23\x32\x8a\x1f\x25\xa2\xc7\x88\x6e\xf6\x23\x1a\x2b\x4f\xc8\xc8\x6b\x78\x79\xe6\xac\x0b\x34\x48\x74\x9c\x8d\x4f\x9e\x3f\xb1\xb5\x84\x67\x74\xb5\xac\x84\xc2\x8e\x67\x5d\x59\xd3\x7d\x79\x82\xeb\xce\xf9\x5c\x90\xf8\xf6\x72\xd5\xec\x17\xba\x40\x1b\xb8\xd0\x0d\x64\xca\x92\x69\xb8\xbf\xc0\x22\x9e\xf4\x3e\xbd\x3d\x67\xe8\xda\xe0\x41\xea\xc6\xae\xc6\x9c\x7e\x36\x1f\xdd\x1f\xa7\xa1\x8c\x1f\x66\x7d\x50\xeb\xa4\x28\x0c\xda\xe8\x9e\x20\xfd\x88\xea\xbc\x39\xea\x1f\x32\xdc\xd6\xb3\xa6\x5f\xba\xb9\x1b\xa9\x1e\xa3\xbd\x6f\xe1\xfe\x1b\x4f\x92\x4e\xfa\xe9\x4b\xe4\x37\x5a\xf6\xb3\x46\xeb\x95\x6a\xda\x67\xc7\x70\x45\x7b\x9d\xd3\x33\x14\x2e\x02\xcf\x55\xbb\x7a\x88\xe0\x20\xed\xdf\x56\x77\x8b\x3f\x02\x22\x7e\x26\x7d\x95\xa5\xc0\xec\xd4\xa2\x8c\x4f\xed\xab\x94\xbf\x60\xff\xc9\x03\x6e\x38\x1e\xb1\xe9\x5d\x17\x33\x78\xbb\x77\x62\x00\xa2\x16\xd3\x7d\xde\x64\x8b\x87\x7f\x7c\x49\x6e\xe7\x3f\xfd\xb9\x1d\x9a\x27\xf7\x9f\xb2\x45\x3c\x36\xbb\x5b\xac\x93\x6c\x91\xde\x7f\x59\xa5\xeb\x2f\xbf\x26\xb7\x37\xab\xf1\xa9\x11\x79\xf1\x82\x75\x7a\xbb\xbc\x61\x12\xf4\x42\xba\x23\xd0\xff\xb1\xe0\xff\xac\x31\x51\xee\xda\x52\xfc\xe9\xc7\x9f\x22\x1b\xe3\x47\x93\xd7\x70\xe8\xf8\x93\xcb\xe0\xe5\xce\x47\xfc\xfc\xb1\xeb\x7c\xe3\xe0\x81\xce\x1f\xba\x17\x5e\xaa\x26\x5f\x27\xff\x09\x00\x00\xff\xff\xcf\x7f\xc7\x9a\x95\x1a\x00\x00")

func _03_auth_schemaGraphqlBytes() ([]byte, error) {
	return bindataRead(
		__03_auth_schemaGraphql,
		"03_auth_schema.graphql",
	)
}

func _03_auth_schemaGraphql() (*asset, error) {
	bytes, err := _03_auth_schemaGraphqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "03_auth_schema.graphql", size: 6805, mode: os.FileMode(436), modTime: time.Unix(1, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"01_base_schema.graphql":   _01_base_schemaGraphql,
	"02_unauth_schema.graphql": _02_unauth_schemaGraphql,
	"03_auth_schema.graphql":   _03_auth_schemaGraphql,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"01_base_schema.graphql":   &bintree{_01_base_schemaGraphql, map[string]*bintree{}},
	"02_unauth_schema.graphql": &bintree{_02_unauth_schemaGraphql, map[string]*bintree{}},
	"03_auth_schema.graphql":   &bintree{_03_auth_schemaGraphql, map[string]*bintree{}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
