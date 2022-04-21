package main

// FIXME copyright
// FIXME license

import (
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh/agent"

	mlog "github.com/jnoxon/ssh-agent-utils/log"
	"github.com/jnoxon/ssh-agent-utils/mux"
	"github.com/rs/zerolog"
)

var (
	listenName = flag.String("listen-socket", "", "path to listening socket")
)

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(),
		"usage: %s -listen-socket <listening-socket-path> <upstream-agent> [<upstream-agent> ...]\n",
		os.Args[0])
}

func main() {

	flag.Usage = usage
	flag.Parse()
	args := flag.Args()

	if *listenName == "" || len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	writer := os.Stderr
	/*
		writer := io.Discard


		// FIXME this doesn't do anything useful on Mac
		_, os.Args[0] = filepath.Split(os.Args[0])
		l, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_NOTICE, os.Args[0])
		if err == nil {
			writer = l
		}
	*/
	logger := zerolog.New(writer)

	a, err := mux.New(&mux.Request{Sockets: args, Logger: writer})
	if err != nil {
		mlog.Fatalf("unable to create new mux: %s", err)
	}

	// To listen on a unix socket, it musn't already exist.
	// If it exists and it's a socket, we remove it. If it exists and it's not
	// a socket, that's an error.
	st, err := os.Stat(*listenName)
	if err != nil {
		if !os.IsNotExist(err) {
			mlog.Fatalf("unable to stat %s: %s", *listenName, err)
		}
	} else {
		if st.Mode()&os.ModeSocket != os.ModeSocket {
			mlog.Fatalf("%s is not a socket (%o)", *listenName, st.Mode())
		}
	}

	// the socket must be removed before we can listen on it
	err = os.RemoveAll(*listenName)
	if err != nil {
		mlog.Fatalf("unable to remove %s: %s", *listenName, err)
	}

	// set the umask so we have safe perms on the listening socket
	mask := syscall.Umask(0177)
	uc, err := net.Listen("unix", *listenName)
	if err != nil {
		mlog.Fatalf("unable to listen on %s: %s", *listenName, err)
	}
	syscall.Umask(mask)

	for {
		logger.Debug().Str("method", "main").Msg("accept_wait")
		fd, err := uc.Accept()
		if err != nil {
			// FIXME should this be fatal?
			logger.Error().Str("method", "main").AnErr("accept_error", err).Send()
			continue
		}
		logger.Debug().Str("method", "main").Msg("accepted")
		go func(a agent.Agent, c net.Conn) {
			l := logger.Info().Str("method", "main")
			defer l.Send()
			err := agent.ServeAgent(a, c)
			c.Close()
			l.AnErr("serve_agent_error", err)
		}(a, fd)
	}
}
