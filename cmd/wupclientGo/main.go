package main

import wupclientgo "github.com/Xpl0itU/wupclientGo"

func main() {
	client, err := wupclientgo.NewWUPClient("192.168.2.158", 1337)
	if err != nil {
		println(err)
		return
	}
	defer client.CloseConnection()

	// Get syslog
	client.DumpSyslog()

	// Send shutdown signal
	client.Svc(0x72, []uint32{0})
}
