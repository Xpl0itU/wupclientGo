package wupclientgo

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

func buffer(size int) []byte {
	return make([]byte, size)
}

func copyString(buffer []byte, s string, offset int) {
	copy(buffer[offset:], []byte(s+"\x00"))
}

func copyWord(buffer []byte, w uint32, offset int) {
	binary.BigEndian.PutUint32(buffer[offset:], w)
}

func getString(buffer []byte, offset int) string {
	end := offset
	for buffer[end] != 0 {
		end++
	}
	return string(buffer[offset:end])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type wupclient struct {
	s         net.Conn
	fsaHandle interface{}
	cwd       string
}

func NewWUPClient(ip string, port int) (*wupclient, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, err
	}
	return &wupclient{
		s: conn,
	}, nil
}

func (c *wupclient) CloseConnection() {
	if c.fsaHandle != nil {
		c.Close(c.fsaHandle.(uint32))
		c.fsaHandle = nil
	}
	c.s.Close()
	c.s = nil
}

func (c *wupclient) Send(command uint32, data []byte) (uint32, []byte, error) {
	request := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(request, command)
	copy(request[4:], data)

	_, err := c.s.Write(request)
	if err != nil {
		return 0, nil, err
	}

	response := make([]byte, 0x600)
	_, err = c.s.Read(response)
	if err != nil {
		return 0, nil, err
	}

	ret := binary.BigEndian.Uint32(response[:4])
	return ret, response[4:], nil
}

func (c *wupclient) Read(addr, length uint32) ([]byte, error) {
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data, addr)
	binary.BigEndian.PutUint32(data[4:], length)
	ret, data, err := c.Send(1, data)
	if err != nil {
		return nil, err
	}
	if ret == 0 {
		return data, nil
	}
	return nil, fmt.Errorf("read error: %08X", ret)
}

func (c *wupclient) Write(addr uint32, data []byte) error {
	buffer := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buffer, addr)
	copy(buffer[4:], data)
	ret, _, err := c.Send(0, buffer)
	if err != nil {
		return err
	}
	if ret == 0 {
		return nil
	}
	return fmt.Errorf("write error: %08X", ret)
}

func (c *wupclient) Svc(svcID uint32, arguments []uint32) (uint32, error) {
	buffer := make([]byte, 4+len(arguments)*4)
	binary.BigEndian.PutUint32(buffer, svcID)
	for i, arg := range arguments {
		offset := 4 + i*4
		binary.BigEndian.PutUint32(buffer[offset:], arg)
	}
	ret, data, err := c.Send(2, buffer)
	if err != nil {
		return 0, err
	}
	if ret == 0 {
		return binary.BigEndian.Uint32(data), nil
	}
	return 0, fmt.Errorf("svc error: %08X", ret)
}

func (c *wupclient) Kill() (uint32, error) {
	ret, _, err := c.Send(3, nil)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) Memcpy(dst, src, length uint32) error {
	buffer := make([]byte, 12)
	binary.BigEndian.PutUint32(buffer, dst)
	binary.BigEndian.PutUint32(buffer[4:], src)
	binary.BigEndian.PutUint32(buffer[8:], length)
	ret, _, err := c.Send(4, buffer)
	if err != nil {
		return err
	}
	if ret == 0 {
		return nil
	}
	return fmt.Errorf("memcpy error: %08X", ret)
}

func (c *wupclient) RepeatWrite(dst, val, n uint32) error {
	buffer := make([]byte, 12)
	binary.BigEndian.PutUint32(buffer, dst)
	binary.BigEndian.PutUint32(buffer[4:], val)
	binary.BigEndian.PutUint32(buffer[8:], n)
	ret, _, err := c.Send(5, buffer)
	if err != nil {
		return err
	}
	if ret == 0 {
		return nil
	}
	return fmt.Errorf("repeatwrite error: %08X", ret)
}

func (c *wupclient) Alloc(size, align uint32) (uint32, error) {
	if size == 0 {
		return 0, nil
	}
	var ret uint32
	if align == 0 {
		ret, err := c.Svc(0x27, []uint32{0xCAFF, size})
		if err != nil {
			return 0, err
		}
		return ret, nil
	}
	ret, err := c.Svc(0x28, []uint32{0xCAFF, size, align})
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) Free(address uint32) (uint32, error) {
	if address == 0 {
		return 0, nil
	}
	ret, err := c.Svc(0x29, []uint32{0xCAFF, address})
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) LoadBuffer(b []byte, align uint32) (uint32, error) {
	if len(b) == 0 {
		return 0, nil
	}
	address, err := c.Alloc(uint32(len(b)), align)
	if err != nil {
		return 0, err
	}
	err = c.Write(address, b)
	if err != nil {
		return 0, err
	}
	return address, nil
}

func (c *wupclient) LoadString(s string, align uint32) (uint32, error) {
	return c.LoadBuffer([]byte(s+"\x00"), align)
}

func (c *wupclient) Open(device string, mode uint32) (uint32, error) {
	address, err := c.LoadString(device, 0)
	if err != nil {
		return 0, err
	}
	handle, err := c.Svc(0x33, []uint32{address, mode})
	if err != nil {
		return 0, err
	}
	_, err = c.Free(address)
	if err != nil {
		return 0, err
	}
	return handle, nil
}

func (c *wupclient) Close(handle uint32) (uint32, error) {
	ret, err := c.Svc(0x34, []uint32{handle})
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) Ioctl(handle, cmd uint32, inbuf []byte, outbufSize uint32) (uint32, []byte, error) {
	inAddress, err := c.LoadBuffer(inbuf, 0)
	if err != nil {
		return 0, nil, err
	}
	var outData []byte
	if outbufSize > 0 {
		outAddress, err := c.Alloc(outbufSize, 0)
		if err != nil {
			return 0, nil, err
		}
		_, err = c.Svc(0x38, []uint32{handle, cmd, inAddress, uint32(len(inbuf)), outAddress, outbufSize})
		if err != nil {
			return 0, nil, err
		}
		outData, err = c.Read(outAddress, outbufSize)
		if err != nil {
			return 0, nil, err
		}
		_, err = c.Free(outAddress)
		if err != nil {
			return 0, nil, err
		}
	} else {
		_, err := c.Svc(0x38, []uint32{handle, cmd, inAddress, uint32(len(inbuf)), 0, 0})
		if err != nil {
			return 0, nil, err
		}
	}
	_, err = c.Free(inAddress)
	if err != nil {
		return 0, nil, err
	}
	return 0, outData, nil
}

func (c *wupclient) Iovec(vecs [][]byte) (uint32, error) {
	var data []byte
	for _, v := range vecs {
		data = append(data, make([]byte, 12)...)
		for i, b := range v {
			offset := len(data) - 12 + i
			data[offset] = b
		}
	}
	address, err := c.LoadBuffer(data, 0)
	if err != nil {
		return 0, err
	}
	return address, nil
}

func (c *wupclient) Ioctlv(handle, cmd uint32, inbufs [][]byte, outbufSizes []uint32, inbufsPtr [][]byte, outbufsPtr [][]byte) (uint32, [][]byte, error) {
	var inbufsWithSizes [][]byte
	for _, b := range inbufs {
		inbufsWithSizes = append(inbufsWithSizes, []byte(b))
	}
	for _, b := range outbufSizes {
		inbufsWithSizes = append(inbufsWithSizes, buffer(int(b)))
	}

	inbufsPointers := make([][]byte, len(inbufsPtr)+len(outbufsPtr))
	copy(inbufsPointers, inbufsPtr)
	copy(inbufsPointers[len(inbufsPtr):], outbufsPtr)

	iovecs, err := c.Iovec(inbufsWithSizes)
	if err != nil {
		return 0, nil, err
	}

	_, err = c.Svc(0x39, []uint32{handle, cmd, uint32(len(inbufs) + len(inbufsPtr)), uint32(len(outbufSizes) + len(outbufsPtr)), iovecs})
	if err != nil {
		return 0, nil, err
	}

	var outData [][]byte
	for _, size := range outbufSizes {
		address, err := c.Read(iovecs, size)
		if err != nil {
			return 0, nil, err
		}
		outData = append(outData, address)
	}

	_, err = c.Free(iovecs)
	if err != nil {
		return 0, nil, err
	}

	return 0, outData, nil
}

func (c *wupclient) FSA_Mount(handle interface{}, devicePath, volumePath string, flags uint32) (uint32, error) {
	inbuffer := buffer(0x520)
	copyString(inbuffer, devicePath, 0x0004)
	copyString(inbuffer, volumePath, 0x0284)
	copyWord(inbuffer, flags, 0x0504)
	_, _, err := c.Ioctlv(handle.(uint32), 0x01, [][]byte{inbuffer, buffer(0)}, []uint32{0x293}, nil, nil)
	if err != nil {
		return 0, err
	}
	return 0, nil
}

func (c *wupclient) FSA_Unmount(handle interface{}, path string, flags uint32) (uint32, error) {
	inbuffer := buffer(0x520)
	copyString(inbuffer, path, 0x4)
	copyWord(inbuffer, flags, 0x284)
	ret, _, err := c.Ioctl(handle.(uint32), 0x02, inbuffer, 0x293)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) FSA_RawOpen(handle interface{}, device string) (uint32, uint32, error) {
	inbuffer := buffer(0x520)
	copyString(inbuffer, device, 0x4)
	ret, data, err := c.Ioctl(handle.(uint32), 0x6A, inbuffer, 0x293)
	if err != nil {
		return 0, 0, err
	}
	return ret, binary.BigEndian.Uint32(data[4:8]), nil
}

func (c *wupclient) FSA_OpenDir(handle interface{}, path string) (uint32, uint32, error) {
	inbuffer := buffer(0x520)
	copyString(inbuffer, path, 0x4)
	ret, data, err := c.Ioctl(handle.(uint32), 0x0A, inbuffer, 0x293)
	if err != nil {
		return 0, 0, err
	}
	return ret, binary.BigEndian.Uint32(data[4:8]), nil
}

func (c *wupclient) FSA_ReadDir(handle interface{}, dirHandle uint32) (uint32, interface{}, error) {
	inbuffer := buffer(0x520)
	copyWord(inbuffer, dirHandle, 0x4)
	ret, data, err := c.Ioctl(handle.(uint32), 0x0B, inbuffer, 0x293)
	data = data[4:]
	if err != nil {
		return 0, nil, err
	}
	if ret == 0 {
		result := map[string]interface{}{
			"name":    getString(data, 0x64),
			"is_file": (data[0x64] & 128) != 128,
			"unk":     data[:0x64],
		}
		return ret, result, nil
	}
	return ret, nil, nil
}

func (c *wupclient) FSA_CloseDir(handle interface{}, dirHandle uint32) (uint32, error) {
	inbuffer := buffer(0x520)
	copyWord(inbuffer, dirHandle, 0x4)
	ret, _, err := c.Ioctl(handle.(uint32), 0x0D, inbuffer, 0x293)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) FSA_OpenFile(handle interface{}, path, mode string) (uint32, uint32, error) {
	inbuffer := buffer(0x520)
	copyString(inbuffer, path, 0x4)
	copyString(inbuffer, mode, 0x284)
	ret, data, err := c.Ioctl(handle.(uint32), 0x0E, inbuffer, 0x293)
	if err != nil {
		return 0, 0, err
	}
	return ret, binary.BigEndian.Uint32(data[4:8]), nil
}

func (c *wupclient) FSA_MakeDir(handle interface{}, path string, flags uint32) (uint32, error) {
	inbuffer := buffer(0x520)
	copyString(inbuffer, path, 0x4)
	copyWord(inbuffer, flags, 0x284)
	ret, _, err := c.Ioctl(handle.(uint32), 0x07, inbuffer, 0x293)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) FSA_ReadFile(handle interface{}, fileHandle, size, cnt uint32) (uint32, []byte, error) {
	inbuffer := buffer(0x520)
	copyWord(inbuffer, size, 0x08)
	copyWord(inbuffer, cnt, 0x0C)
	copyWord(inbuffer, fileHandle, 0x14)
	ret, data, err := c.Ioctlv(handle.(uint32), 0x0F, [][]byte{inbuffer}, []uint32{size * cnt, 0x293}, nil, nil)
	if err != nil {
		return 0, nil, err
	}
	return ret, data[0], nil
}

func (c *wupclient) FSA_WriteFile(handle interface{}, fileHandle uint32, data []byte) (uint32, error) {
	inbuffer := buffer(0x520)
	copyWord(inbuffer, 1, 0x08)                 // size
	copyWord(inbuffer, uint32(len(data)), 0x0C) // cnt
	copyWord(inbuffer, fileHandle, 0x14)
	ret, _, err := c.Ioctlv(handle.(uint32), 0x10, [][]byte{inbuffer, data}, []uint32{0x293}, nil, nil)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) FSA_ReadFilePtr(handle interface{}, fileHandle, size, cnt uint32, ptr []byte) (uint32, []byte, error) {
	inbuffer := buffer(0x520)
	copyWord(inbuffer, size, 0x08)
	copyWord(inbuffer, cnt, 0x0C)
	copyWord(inbuffer, fileHandle, 0x14)
	ptrData := make([]byte, len(ptr))
	copy(ptrData, ptr)
	ret, data, err := c.Ioctlv(handle.(uint32), 0x0F, [][]byte{inbuffer}, []uint32{0x293}, nil, [][]byte{ptrData})
	if err != nil {
		return 0, nil, err
	}
	return ret, data[0], nil
}

func (c *wupclient) FSA_WriteFilePtr(handle interface{}, fileHandle, size, cnt uint32, ptr []byte) (uint32, error) {
	inbuffer := buffer(0x520)
	copyWord(inbuffer, size, 0x08)
	copyWord(inbuffer, cnt, 0x0C)
	copyWord(inbuffer, fileHandle, 0x14)
	ptrData := make([]byte, len(ptr))
	copy(ptrData, ptr)
	ret, _, err := c.Ioctlv(handle.(uint32), 0x10, [][]byte{inbuffer, ptrData}, []uint32{0x293, size * cnt}, nil, nil)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) FSA_GetStatFile(handle interface{}, fileHandle uint32) (uint32, []uint32, error) {
	inbuffer := buffer(0x520)
	copyWord(inbuffer, fileHandle, 0x4)
	ret, data, err := c.Ioctl(handle.(uint32), 0x14, inbuffer, 0x64)
	if err != nil {
		return 0, nil, err
	}
	stats := make([]uint32, 27)
	for i := 0; i < 27; i++ {
		stats[i] = binary.BigEndian.Uint32(data[i*4 : (i+1)*4])
	}
	return ret, stats, nil
}

func (c *wupclient) FSA_CloseFile(handle interface{}, fileHandle uint32) (uint32, error) {
	inbuffer := buffer(0x520)
	copyWord(inbuffer, fileHandle, 0x4)
	ret, _, err := c.Ioctl(handle.(uint32), 0x15, inbuffer, 0x293)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) FSA_ChangeMode(handle interface{}, path string, mode uint32) (uint32, error) {
	mask := uint32(0x777)
	inbuffer := buffer(0x520)
	copyString(inbuffer, path, 0x0004)
	copyWord(inbuffer, mode, 0x0284)
	copyWord(inbuffer, mask, 0x0288)
	ret, _, err := c.Ioctl(handle.(uint32), 0x20, inbuffer, 0x293)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) FSA_Remove(handle interface{}, path string) (uint32, error) {
	inbuffer := buffer(0x520)
	copyString(inbuffer, path, 0x04)
	ret, _, err := c.Ioctl(handle.(uint32), 0x08, inbuffer, 0x293)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) FSA_FlushVolume(handle interface{}, path string) (uint32, error) {
	inbuffer := buffer(0x520)
	copyString(inbuffer, path, 0x04)
	ret, _, err := c.Ioctl(handle.(uint32), 0x1B, inbuffer, 0x293)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) MCP_InstallGetInfo(handle interface{}, path string) (uint32, []uint32, error) {
	inbuffer := buffer(0x27F)
	copyString(inbuffer, path, 0x0)
	ret, data, err := c.Ioctlv(handle.(uint32), 0x80, [][]byte{inbuffer}, []uint32{0x16}, nil, nil)
	if err != nil {
		return 0, nil, err
	}
	info := make([]uint32, 6)
	for i := 0; i < 6; i++ {
		info[i] = binary.BigEndian.Uint32(data[0][i*4 : (i+1)*4])
	}
	return ret, info, nil
}

func (c *wupclient) MCP_Install(handle interface{}, path string) (uint32, error) {
	inbuffer := buffer(0x27F)
	copyString(inbuffer, path, 0x0)
	ret, _, err := c.Ioctlv(handle.(uint32), 0x81, [][]byte{inbuffer}, nil, nil, nil)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) MCP_InstallGetProgress(handle interface{}) (uint32, []uint32, error) {
	ret, data, err := c.Ioctl(handle.(uint32), 0x82, nil, 0x24)
	if err != nil {
		return 0, nil, err
	}
	progress := make([]uint32, 9)
	for i := 0; i < 9; i++ {
		progress[i] = binary.BigEndian.Uint32(data[i*4 : (i+1)*4])
	}
	return ret, progress, nil
}

func (c *wupclient) MCP_DeleteTitle(handle interface{}, path string, flush uint32) (uint32, error) {
	inbuffer := buffer(0x38)
	copyString(inbuffer, path, 0x0)
	inbuffer2 := buffer(0x4)
	copyWord(inbuffer2, flush, 0x0)
	ret, _, err := c.Ioctlv(handle.(uint32), 0x83, [][]byte{inbuffer, inbuffer2}, nil, nil, nil)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) MCP_CopyTitle(handle interface{}, path string, dstDeviceID, flush uint32) (uint32, error) {
	inbuffer := buffer(0x27F)
	copyString(inbuffer, path, 0x0)
	inbuffer2 := buffer(0x4)
	copyWord(inbuffer2, dstDeviceID, 0x0)
	inbuffer3 := buffer(0x4)
	copyWord(inbuffer3, flush, 0x0)
	ret, _, err := c.Ioctlv(handle.(uint32), 0x85, [][]byte{inbuffer, inbuffer2, inbuffer3}, nil, nil, nil)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) MCP_InstallSetTargetDevice(handle interface{}, device uint32) (uint32, error) {
	inbuffer := buffer(0x4)
	copyWord(inbuffer, device, 0x0)
	ret, _, err := c.Ioctl(handle.(uint32), 0x8D, inbuffer, 0)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) MCP_InstallSetTargetUsb(handle interface{}, device uint32) (uint32, error) {
	inbuffer := buffer(0x4)
	copyWord(inbuffer, device, 0x0)
	ret, _, err := c.Ioctl(handle.(uint32), 0xF1, inbuffer, 0)
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func (c *wupclient) DumpSyslog() {
	value, err := c.Read(0x05095ECC, 4)
	if err != nil {
		fmt.Println("Failed to read syslog:", err)
		return
	}
	syslogAddress := binary.BigEndian.Uint32(value) + 0x10
	blockSize := 0x400
	for i := uint32(0); i < 0x40000; i += uint32(blockSize) {
		data, err := c.Read(syslogAddress+i, uint32(blockSize))
		if err != nil {
			fmt.Println("Failed to read syslog:", err)
			return
		}
		fmt.Println(string(data))
	}
}

func (c *wupclient) GetFSAHandle() uint32 {
	if c.fsaHandle == 0 {
		c.fsaHandle, _ = c.Open("/dev/fsa", 0)
		if c.fsaHandle == 0 {
			fmt.Println("Failed to open fsa")
			return 0
		}
	}
	return c.fsaHandle.(uint32)
}

func (c *wupclient) Mkdir(path string, flags uint32) uint32 {
	fsaHandle := c.GetFSAHandle()
	if path[0] != '/' {
		path = c.cwd + "/" + path
	}
	ret, err := c.FSA_MakeDir(fsaHandle, path, flags)
	if err != nil {
		fmt.Printf("mkdir error (%s, %08X)\n", path, ret)
		return ret
	}
	if ret == 0 {
		return 0
	} else {
		fmt.Printf("mkdir error (%s, %08X)\n", path, ret)
		return ret
	}
}

func (c *wupclient) Chmod(filename string, flags uint32) {
	fsaHandle := c.GetFSAHandle()
	if filename[0] != '/' {
		filename = c.cwd + "/" + filename
	}
	ret, err := c.FSA_ChangeMode(fsaHandle, filename, flags)
	if err != nil {
		fmt.Printf("chmod error (%s, %08X)\n", filename, ret)
		return
	}
	fmt.Printf("chmod returned : %X\n", ret)
}

func (c *wupclient) Cd(path string) int32 {
	if path[0] != '/' && c.cwd[0] == '/' {
		return c.Cd(c.cwd + "/" + path)
	}
	fsaHandle := c.GetFSAHandle()
	ret, dirHandle, err := c.FSA_OpenDir(fsaHandle, path)
	if err != nil {
		fmt.Printf("cd error : %X\n", ret)
		return -1
	}
	if ret == 0 {
		c.cwd = path
		c.FSA_CloseDir(fsaHandle, dirHandle)
		return 0
	} else {
		fmt.Printf("cd error : path does not exist (%s)\n", path)
		return -1
	}
}

func (c *wupclient) Ls(path string, returnData bool) interface{} {
	fsaHandle := c.GetFSAHandle()
	if path != "" && path[0] != '/' {
		path = c.cwd + "/" + path
	}
	ret, dirHandle, err := c.FSA_OpenDir(fsaHandle, path)
	if err != nil {
		fmt.Printf("ls error : %X\n", ret)
		return nil
	}
	if ret != 0 {
		fmt.Printf("opendir error : %X\n", ret)
		if returnData {
			return nil
		}
		return []byte{}
	}
	entries := make([]interface{}, 0)
	for {
		ret, data, err := c.FSA_ReadDir(fsaHandle, dirHandle)
		if err != nil {
			fmt.Printf("readdir error : %X\n", ret)
			break
		}
		if ret != 0 {
			break
		}
		if !returnData {
			dataMap := data.(map[string]interface{})
			if dataMap["is_file"].(bool) {
				fmt.Printf("     %s\n", dataMap["name"].(string))
			} else {
				fmt.Printf("     %s/\n", dataMap["name"].(string))
			}
		} else {
			entries = append(entries, data)
		}
	}
	c.FSA_CloseDir(fsaHandle, dirHandle)
	if returnData {
		return entries
	}
	return nil
}

func (c *wupclient) DlDir(path string) {
	if path[0] != '/' {
		path = c.cwd + "/" + path
	}
	entries := c.Ls(path, true).([]interface{})
	for _, e := range entries {
		entry := e.(map[string]interface{})
		if entry["is_file"].(bool) {
			fmt.Println(entry["name"].(string))
			c.Dl(path+"/"+entry["name"].(string), path[1:], "")
		} else {
			fmt.Println(entry["name"].(string) + "/")
			c.DlDir(path + "/" + entry["name"].(string))
		}
	}
}

func (c *wupclient) CpDir(srcpath, dstpath string) {
	entries := c.Ls(srcpath, true).([]interface{})
	q := make([][3]interface{}, 0)
	for _, e := range entries {
		entry := e.(map[string]interface{})
		q = append(q, [3]interface{}{srcpath, dstpath, entry})
	}
	for len(q) > 0 {
		entry := q[len(q)-1]
		q = q[:len(q)-1]
		_srcpath := entry[0].(string) + "/" + entry[2].(map[string]interface{})["name"].(string)
		_dstpath := entry[1].(string) + "/" + entry[2].(map[string]interface{})["name"].(string)
		if entry[2].(map[string]interface{})["is_file"].(bool) {
			fmt.Println(entry[2].(map[string]interface{})["name"].(string))
			c.Cp(_srcpath, _dstpath)
		} else {
			c.Mkdir(_dstpath, 0x600)
			subEntries := c.Ls(_srcpath, true).([]interface{})
			for _, subEntry := range subEntries {
				q = append(q, [3]interface{}{_srcpath, _dstpath, subEntry})
			}
		}
	}
}

func (c *wupclient) Pwd() string {
	return c.cwd
}

func (c *wupclient) Cp(filenameIn, filenameOut string) {
	fsaHandle := c.GetFSAHandle()
	ret, inFileHandle, err := c.FSA_OpenFile(fsaHandle, filenameIn, "r")
	if err != nil {
		fmt.Printf("cp error: could not open %s\n", filenameIn)
		return
	}
	if ret != 0 {
		fmt.Printf("cp error: could not open %s\n", filenameIn)
		return
	}
	ret, outFileHandle, err := c.FSA_OpenFile(fsaHandle, filenameOut, "w")
	if err != nil {
		fmt.Printf("cp error: could not open %s\n", filenameOut)
		return
	}
	if ret != 0 {
		fmt.Printf("cp error: could not open %s\n", filenameOut)
		return
	}
	blockSize := 0x10000
	buffer, err := c.Alloc(uint32(blockSize), 0x40)
	if err != nil {
		fmt.Printf("cp error: could not allocate buffer\n")
		return
	}
	k := uint32(0)
	for {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, buffer)
		ret, _, err := c.FSA_ReadFilePtr(fsaHandle, inFileHandle, 0x1, uint32(blockSize), buf)
		if err != nil {
			fmt.Printf("cp error: could not read file\n")
			return
		}
		k += ret
		ret, err = c.FSA_WriteFilePtr(fsaHandle, outFileHandle, 0x1, ret, buf)
		if err != nil {
			fmt.Printf("cp error: could not write file\n")
			return
		}
		fmt.Printf("%X\r", k)
		if ret < uint32(blockSize) {
			break
		}
	}
	c.Free(buffer)
	c.FSA_CloseFile(fsaHandle, outFileHandle)
	c.FSA_CloseFile(fsaHandle, inFileHandle)
}

func (c *wupclient) Df(filenameOut string, src []byte, size uint32) {
	fsaHandle := c.GetFSAHandle()
	ret, outFileHandle, err := c.FSA_OpenFile(fsaHandle, filenameOut, "w")
	if err != nil {
		fmt.Printf("df error: could not open %s\n", filenameOut)
		return
	}
	if ret != 0 {
		fmt.Printf("df error: could not open %s\n", filenameOut)
		return
	}
	blockSize := 0x10000
	buffer, err := c.Alloc(uint32(blockSize), 0x40)
	if err != nil {
		fmt.Printf("df error: could not allocate buffer\n")
		return
	}
	k := uint32(0)
	for k < size {
		curSize := min(int(size-k), blockSize)
		c.Memcpy(buffer, binary.BigEndian.Uint32(src[k:]), uint32(curSize))
		k += uint32(curSize)
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, buffer)
		_, err := c.FSA_WriteFilePtr(fsaHandle, outFileHandle, 0x1, uint32(curSize), buf)
		if err != nil {
			fmt.Printf("df error: could not write file\n")
			return
		}
		fmt.Printf("%X (%f) \r", k, float64(k*100)/float64(size))
	}
	c.Free(buffer)
	c.FSA_CloseFile(fsaHandle, outFileHandle)
}

func (c *wupclient) DlBuf(filename string, showProgress bool) []byte {
	fsaHandle := c.GetFSAHandle()
	if filename[0] != '/' {
		filename = c.cwd + "/" + filename
	}
	ret, fileHandle, err := c.FSA_OpenFile(fsaHandle, filename, "r")
	if err != nil {
		fmt.Printf("dl error: could not open %s\n", filename)
		return nil
	}
	if ret != 0 {
		fmt.Printf("dl error: could not open %s\n", filename)
		return nil
	}
	buf := make([]byte, 0)
	blockSize := 0x400
	for {
		ret, data, err := c.FSA_ReadFile(fsaHandle, fileHandle, 0x1, uint32(blockSize))
		if err != nil {
			fmt.Printf("dl error: could not read file\n")
			return nil
		}
		buf = append(buf, data[:ret]...)
		if showProgress {
			fmt.Printf("%X\r", len(buf))
		}
		if ret < uint32(blockSize) {
			break
		}
	}
	c.FSA_CloseFile(fsaHandle, fileHandle)
	return buf
}

func (c *wupclient) Dl(filename, directoryPath, localFilename string) int32 {
	buf := c.DlBuf(filename, true)
	if buf == nil {
		return -1
	}
	if localFilename == "" {
		if index := strings.LastIndex(filename, "/"); index != -1 {
			localFilename = filename[index+1:]
		} else {
			localFilename = filename
		}
	}
	if directoryPath == "" {
		dirPath, _ := filepath.Abs(filepath.Dir(os.Args[0]))
		dirPath = strings.ReplaceAll(dirPath, "\\", "/")
		fullPath := dirPath + "/" + directoryPath + "/"
		fullPath = strings.ReplaceAll(fullPath, "//", "/")
		mkdirP(fullPath)
		os.WriteFile(fullPath+localFilename, buf, 0644)
	} else {
		dirPath, _ := filepath.Abs(filepath.Dir(os.Args[0]))
		dirPath = strings.ReplaceAll(dirPath, "\\", "/")
		fullPath := dirPath + "/" + directoryPath + "/"
		fullPath = strings.ReplaceAll(fullPath, "//", "/")
		mkdirP(fullPath)
		os.WriteFile(fullPath+localFilename, buf, 0644)
	}
	return 0
}

func mkdirP(path string) {
	_ = os.MkdirAll(path, os.ModePerm)
}

func (c *wupclient) Fr(filename string, offset, size uint32) []byte {
	fsaHandle := c.GetFSAHandle()
	if filename[0] != '/' {
		filename = c.cwd + "/" + filename
	}
	ret, fileHandle, err := c.FSA_OpenFile(fsaHandle, filename, "r")
	if err != nil {
		fmt.Printf("fr error: could not open %s\n", filename)
		return nil
	}
	if ret != 0 {
		fmt.Printf("fr error : could not open %s\n", filename)
		return nil
	}
	buffer := make([]byte, 0)
	blockSize := 0x400
	for {
		ret, data, err := c.FSA_ReadFile(fsaHandle, fileHandle, 0x1, uint32(min(blockSize, int(size))))
		if err != nil {
			fmt.Printf("fr error: could not read file\n")
			return nil
		}
		buffer = append(buffer, data[:ret]...)
		fmt.Printf("%X\r", len(buffer))
		if len(buffer) >= int(size) {
			break
		}
	}
	c.FSA_CloseFile(fsaHandle, fileHandle)
	return buffer
}

func (c *wupclient) Fw(filename string, offset uint32, buffer []byte) {
	fsaHandle := c.GetFSAHandle()
	if filename[0] != '/' {
		filename = c.cwd + "/" + filename
	}
	ret, fileHandle, err := c.FSA_OpenFile(fsaHandle, filename, "r+")
	if err != nil {
		fmt.Printf("fw error: could not open %s\n", filename)
		return
	}
	if ret != 0 {
		fmt.Printf("fw error : could not open %s\n", filename)
		return
	}
	blockSize := 0x400
	k := 0
	for {
		curSize := min(len(buffer)-k, blockSize)
		if curSize <= 0 {
			break
		}
		fmt.Printf("%X\r", k)
		ret, err := c.FSA_WriteFile(fsaHandle, fileHandle, buffer[k:(k+curSize)])
		if err != nil {
			fmt.Printf("fw error: could not write file\n")
			return
		}
		k += curSize
		if ret < 0 {
			break
		}
	}
	c.FSA_CloseFile(fsaHandle, fileHandle)
}

func (c *wupclient) Stat(filename string) {
	fsaHandle := c.GetFSAHandle()
	if filename[0] != '/' {
		filename = c.cwd + "/" + filename
	}
	ret, fileHandle, err := c.FSA_OpenFile(fsaHandle, filename, "r")
	if err != nil {
		fmt.Printf("stat error: could not open %s\n", filename)
		return
	}
	if ret != 0 {
		fmt.Printf("stat error: could not open %s\n", filename)
		return
	}
	ret, stats, err := c.FSA_GetStatFile(fsaHandle, fileHandle)
	if err != nil {
		fmt.Printf("stat error: %X\n", ret)
		return
	}
	if ret != 0 {
		fmt.Printf("stat error: %X\n", ret)
	} else {
		fmt.Printf("flags: %X\n", stats[1])
		fmt.Printf("mode: %X\n", stats[2])
		fmt.Printf("owner: %X\n", stats[3])
		fmt.Printf("group: %X\n", stats[4])
		fmt.Printf("size: %X\n", stats[5])
	}
	c.FSA_CloseFile(fsaHandle, fileHandle)
}

func (c *wupclient) askyesno() bool {
	yes := map[string]bool{"yes": true, "ye": true, "y": true}
	no := map[string]bool{"no": true, "n": true, "": true}
	for {
		reader := bufio.NewReader(os.Stdin)
		choice, _ := reader.ReadString('\n')
		choice = strings.ToLower(strings.TrimSpace(choice))
		if yes[choice] {
			return true
		} else if no[choice] {
			return false
		} else {
			fmt.Println("Please respond with 'y' or 'n'")
		}
	}
}

func (c *wupclient) Rm(filename string) {
	fsaHandle := c.GetFSAHandle()
	if filename[0] != '/' {
		filename = c.cwd + "/" + filename
	}
	ret, fileHandle, err := c.FSA_OpenFile(fsaHandle, filename, "r")
	if err != nil {
		fmt.Printf("rm error: could not open %s\n", filename)
		return
	}
	if ret != 0 {
		fmt.Printf("rm error: could not open %s (%X)\n", filename, ret)
		return
	}
	c.FSA_CloseFile(fsaHandle, fileHandle)
	fmt.Println("WARNING: REMOVING A FILE CAN BRICK YOUR CONSOLE, ARE YOU SURE (Y/N)?")
	if c.askyesno() {
		ret, err = c.FSA_Remove(fsaHandle, filename)
		if err != nil {
			fmt.Printf("rm error: %X\n", ret)
			return
		}
		fmt.Printf("rm: %X\n", ret)
	} else {
		fmt.Println("rm aborted")
	}
}

func (c *wupclient) RmDir(path string) {
	fsaHandle := c.GetFSAHandle()
	if path[0] != '/' {
		path = c.cwd + "/" + path
	}
	ret, dirHandle, err := c.FSA_OpenDir(fsaHandle, path)
	if err != nil {
		fmt.Printf("rmdir error: could not open %s\n", path)
		return
	}
	if ret != 0 {
		fmt.Printf("rmdir error: could not open %s (%X)\n", path, ret)
		return
	}
	c.FSA_CloseDir(fsaHandle, dirHandle)
	entries := c.Ls(path, true)
	if len(entries.([]interface{})) != 0 {
		fmt.Println("rmdir error: directory not empty!")
		return
	}
	fmt.Println("WARNING: REMOVING A DIRECTORY CAN BRICK YOUR CONSOLE, ARE YOU SURE (Y/N)?")
	if c.askyesno() {
		ret, err = c.FSA_Remove(fsaHandle, path)
		if err != nil {
			fmt.Printf("rmdir error: %X\n", ret)
			return
		}
		fmt.Printf("rmdir: %X\n", ret)
	} else {
		fmt.Println("rmdir aborted")
	}
}

func (c *wupclient) Up(localFilename, filename string) {
	fsaHandle := c.GetFSAHandle()
	if filename == "" {
		if index := strings.LastIndex(localFilename, "/"); index != -1 {
			filename = localFilename[index+1:]
		} else {
			filename = localFilename
		}
	}
	if filename[0] != '/' {
		filename = c.cwd + "/" + filename
	}
	f, err := os.Open(localFilename)
	if err != nil {
		fmt.Printf("up error: could not open %s\n", filename)
		return
	}
	ret, fileHandle, err := c.FSA_OpenFile(fsaHandle, filename, "w")
	if err != nil {
		fmt.Printf("up error: could not open %s\n", filename)
		return
	}
	if ret != 0 {
		fmt.Printf("up error: could not open %s\n", filename)
		return
	}
	progress := uint32(0)
	blockSize := 0x400
	data := make([]byte, blockSize)
	for {
		bytesRead, err := f.Read(data)
		if err != nil || bytesRead == 0 {
			break
		}
		_, err = c.FSA_WriteFile(fsaHandle, fileHandle, data[:bytesRead])
		if err != nil {
			fmt.Printf("up error: could not write file\n")
			return
		}
		progress += uint32(bytesRead)
		fmt.Printf("%X\r", progress)
		if bytesRead < blockSize {
			break
		}
	}
	c.FSA_CloseFile(fsaHandle, fileHandle)
}
