package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/jnoxon/ssh-agent-utils/filter"
	"golang.org/x/crypto/ssh/agent"
)

/*

TODO:

- Remove panics, add resilience

- Add modes. Maybe "add | remove | list | listen"
	On Mac, this should manage user agents with launchd.
	On Linux, this should do something with systemd.
	On other architectures, add | remove should fail.

- Maybe add comments

- Check perms in dir containing socket.

- Documentation

- Publish

- Homebrew

- Links, e.g. https://github.com/maxgoedjen/secretive

*/

var (
	listenName   = flag.String("listen-socket", "", "path to listening socket")
	upstreamName = flag.String("upstream-agent", os.Getenv("SSH_AUTH_SOCK"), "path to the ssh agent socket")
	fingerprints = flag.String("fingerprints", "", "fingerprint(s) to match; can be partial; can be MD5 or SHA256. Separate multiples with comma.")
)

func main() {
	flag.Parse()

	if *listenName == "" || *upstreamName == "" || *fingerprints == "" {
		flag.Usage()
		os.Exit(1)
	}

	up, err := net.Dial("unix", *upstreamName)
	if err != nil {
		panic(err)
	}
	upstream := agent.NewClient(up)

	// fixme, this is common code from agent-mux, stick it somewhere else
	st, err := os.Stat(*listenName)
	if err != nil {
		if !os.IsNotExist(err) {
			// it exists, but we can't stat it?
			panic(err)
		}
	} else {
		if st.Mode()&os.ModeSocket != os.ModeSocket {
			panic(fmt.Sprintf("%s is not a socket (%o)", *listenName, st.Mode()))
		}
	}

	sockDir := filepath.Dir(*listenName)
	sockDir, err = filepath.Abs(sockDir)
	if err != nil {
		panic(err)
	}
	st, err = os.Stat(sockDir)
	if err != nil {
		panic(err)
	}
	if !st.IsDir() {
		panic(fmt.Sprintf("%s: not a directory", sockDir))
	}

	err = os.RemoveAll(*listenName)
	if err != nil {
		panic(err)
	}

	mask := syscall.Umask(0177)
	uc, err := net.Listen("unix", *listenName)
	if err != nil {
		panic(err)
	}
	syscall.Umask(mask)

	// fingerprints could be validated better, checked for empties, etc.
	filterAgent := filter.New(upstream, strings.Split(*fingerprints, ","))

	for {
		fd, err := uc.Accept()
		if err != nil {
			panic(err) // FIXME
		}
		go agent.ServeAgent(filterAgent, fd)
	}
}
