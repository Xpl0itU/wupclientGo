package main

import (
	"fmt"

	wupclientgo "github.com/Xpl0itU/wupclientGo"
)

func main() {
	client, err := wupclientgo.NewWUPClient("192.168.2.158", 1337)
	if err != nil {
		println(err)
		return
	}
	defer client.CloseConnection()

	fmt.Println(client.Ls("/vol/storage_mlc01", true))
}
