// Command probe is the CI check that runs inside the reference compartment.
// It is not an agent. Distroless has no shell, so the e2e job execs this
// binary to dial a TCP address, to create a file on the compartment tmpfs,
// or to count processes by name.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
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

// countProcs counts processes whose /proc/<pid>/comm equals name. The e2e
// job uses it to show a bridge's child process is gone once its session
// ended. A process that exits between the glob and the read is skipped.
func countProcs(name string) (int, error) {
	matches, err := filepath.Glob("/proc/[0-9]*/comm")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(data)) == name {
			n++
		}
	}
	return n, nil
}

func main() {
	dial := flag.String("dial", "", "dial tcp host:port and exit 0 only if the connect succeeds")
	touchPath := flag.String("touch", "", "create a file and exit")
	procs := flag.String("procs", "", "print the number of processes whose /proc/<pid>/comm equals this name, then exit")
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
	if *procs != "" {
		n, err := countProcs(*procs)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(n)
		return
	}
	log.Fatal("set -dial host:port, -touch path, or -procs name")
}
