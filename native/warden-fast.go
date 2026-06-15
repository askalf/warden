// warden-fast — a tiny native Claude Code PreToolUse hook client.
//
// It forwards the hook's stdin to the warden daemon over loopback TCP and
// prints back exactly what the daemon says to print. Cold start is ~1-3ms vs
// ~130ms for a node hook, so warden can screen every single tool call without
// any felt latency.
//
// It is a pure byte pipe: it parses none of the hook payload, holds no policy,
// runs no classifier. All of that lives in the daemon, the single source of
// truth. Fail-open by design: any error (no daemon, timeout, short read) exits
// 0 with no output, so a warden hiccup can never block your tooling. When the
// daemon is down, Claude Code simply proceeds — the node hook remains the
// safe, daemon-free fallback if you register it instead.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const dialTimeout = 1500 * time.Millisecond

// Same discovery file the daemon writes (see src/client.mjs wardenInfoFile).
func infoPath() string {
	if v := os.Getenv("WARDEN_INFO"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".warden", "daemon.json")
}

func main() {
	// 1. Claude Code's hook payload arrives on stdin (compact JSON, one line).
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(0) // fail-open
	}
	payload := bytes.TrimRight(in, " \t\r\n")
	if len(payload) == 0 {
		os.Exit(0)
	}

	// 2. Find the daemon's loopback port from the 0600 discovery file.
	ip := infoPath()
	if ip == "" {
		os.Exit(0)
	}
	raw, err := os.ReadFile(ip)
	if err != nil {
		os.Exit(0) // no daemon running -> defer (CC proceeds)
	}
	var info struct {
		Port int `json:"port"`
	}
	if json.Unmarshal(raw, &info) != nil || info.Port <= 0 {
		os.Exit(0)
	}

	// 3. Forward `<payload>\n`, read back one line, print the bytes before it.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Port)), dialTimeout)
	if err != nil {
		os.Exit(0) // daemon down -> fail-open
	}
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	if _, err := conn.Write(append(payload, '\n')); err != nil {
		_ = conn.Close()
		os.Exit(0)
	}

	buf := make([]byte, 0, 512)
	tmp := make([]byte, 512)
	for {
		n, rerr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if i := bytes.IndexByte(buf, '\n'); i >= 0 {
				// deny/ask -> a hookSpecificOutput JSON; defer/allow -> empty.
				_, _ = os.Stdout.Write(buf[:i])
				_ = conn.Close()
				os.Exit(0)
			}
		}
		if rerr != nil {
			break
		}
	}
	_ = conn.Close()
	os.Exit(0) // no newline seen -> defer
}
