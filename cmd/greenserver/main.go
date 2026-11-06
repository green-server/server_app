// Command greenserver is the Green Server agent.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/green-server/server_app/internal/agent"
	"github.com/green-server/server_app/internal/metrics"
)

var version = "dev" // set with -ldflags "-X main.version=..."

const usage = `usage:
  greenserver run --server wss://host/ws/agent [--token T] [--idle-watts W] [--max-watts W] [--state-dir DIR]
  greenserver hook pre|post [--socket PATH]
  greenserver mcp-approve [--socket PATH]
  greenserver version

The token can also come from GREENSERVER_TOKEN, which keeps it out of ps output.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "run":
		run(args)
	case "hook":
		hook(args)
	case "mcp-approve":
		fs := flag.NewFlagSet("mcp-approve", flag.ExitOnError)
		socket := fs.String("socket", defaultSocket(), "agent socket")
		fs.Parse(args)
		if err := agent.ServeMCP(os.Stdin, os.Stdout, *socket); err != nil {
			log.Fatal(err)
		}
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".greenserver"
	}
	return filepath.Join(home, ".greenserver")
}

func defaultSocket() string { return agent.SocketPath(defaultStateDir()) }

func run(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	server := fs.String("server", "", "backend URL, wss://host/ws/agent")
	token := fs.String("token", "", "agent token; prefer the GREENSERVER_TOKEN environment variable")
	idle := fs.Float64("idle-watts", 15, "estimated watts at 0% CPU, used when power cannot be measured")
	maxW := fs.Float64("max-watts", 75, "estimated watts at 100% CPU, used when power cannot be measured")
	stateDir := fs.String("state-dir", defaultStateDir(), "directory for the socket and audit log")
	fs.Parse(args)

	if *token == "" {
		*token = os.Getenv("GREENSERVER_TOKEN")
	}
	os.Unsetenv("GREENSERVER_TOKEN")

	a, err := agent.New(agent.Config{
		Server: *server, Token: *token, StateDir: *stateDir, Version: version,
		Profile: metrics.Profile{IdleWatts: *idle, MaxWatts: *maxW},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

func hook(args []string) {
	// Claude reads exit 2 as "block", and anything else from a pre hook as
	// "carry on", so even a usage error has to block.
	if len(args) < 1 || args[0] != "pre" && args[0] != "post" {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	socket := fs.String("socket", defaultSocket(), "agent socket")
	if err := fs.Parse(args[1:]); err != nil {
		os.Exit(2)
	}
	os.Exit(agent.Hook(args[0], os.Stdin, os.Stdout, os.Stderr, *socket))
}
