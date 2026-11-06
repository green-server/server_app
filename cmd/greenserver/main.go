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
	"strings"
	"syscall"

	"github.com/green-server/server_app/internal/agent"
	"github.com/green-server/server_app/internal/metrics"
	"github.com/green-server/server_app/internal/priv"
)

var version = "dev" // set with -ldflags "-X main.version=..."

const usage = `usage:
  greenserver run --server wss://host/ws/agent [--token T] [--idle-watts W] [--max-watts W] [--state-dir DIR]
  greenserver hook pre|post [--socket PATH]
  greenserver mcp-approve [--socket PATH]
  greenserver priv docker|systemctl|cpupower|powerprofilesctl ...
  greenserver root-helper --public-key KEY --server-id N [--socket PATH] [--group NAME]
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
	case "priv":
		privileged(args)
	case "root-helper":
		rootHelper(args)
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

// privileged runs one command through the root helper. It needs the grant the
// owner's browser approval produced, so running it by hand does nothing.
func privileged(args []string) {
	command := priv.Prefix + strings.Join(args, " ")
	if _, err := priv.Parse(command); err != nil {
		log.Fatal(err)
	}
	socket := os.Getenv("GREENSERVER_SOCKET")
	if socket == "" {
		socket = defaultSocket()
	}
	grant, err := agent.TakeGrant(socket, command)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := priv.Call(priv.DefaultSocket, priv.Request{Command: command, Grant: *grant})
	if err != nil {
		log.Fatal(err)
	}
	if resp.Error != "" {
		fmt.Fprintln(os.Stderr, "greenserver:", resp.Error)
	}
	fmt.Print(resp.Output)
	os.Exit(resp.ExitCode)
}

func rootHelper(args []string) {
	fs := flag.NewFlagSet("root-helper", flag.ExitOnError)
	key := fs.String("public-key", "", "backend grant public key, base64")
	server := fs.Int64("server-id", 0, "id of this server on the backend")
	socket := fs.String("socket", priv.DefaultSocket, "socket to listen on")
	group := fs.String("group", "greenserver", "group allowed to use the socket")
	fs.Parse(args)
	h, err := priv.NewHelper(*key, *server)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := h.Serve(ctx, *socket, *group); err != nil {
		log.Fatal(err)
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
