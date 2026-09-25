// Command probe is the CI check that runs inside the reference compartment.
// It is not an agent. Distroless has no shell, so the e2e job execs this
// binary to dial a TCP address or to create a file on the compartment tmpfs.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"time"
)

func dialTCP(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

func touch(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}

func main() {
	dial := flag.String("dial", "", "dial tcp host:port and exit 0 only if the connect succeeds")
	touchPath := flag.String("touch", "", "create a file and exit")
	flag.Parse()

	if *dial != "" {
		if err := dialTCP(*dial); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *touchPath != "" {
		if err := touch(*touchPath); err != nil {
			log.Fatal(err)
		}
		return
	}
	log.Fatal("set -dial host:port or -touch path")
}
