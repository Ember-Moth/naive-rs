// Separate-process loopback origin for performance runs (no Python/GIL bottleneck).
package main

import (
	"fmt"
	"io"
	"net"
)

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Println(listener.Addr().(*net.TCPAddr).Port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
	}
}
