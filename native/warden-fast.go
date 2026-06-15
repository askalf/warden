// warden-fast — a tiny native Claude Code PreToolUse hook client.
//
// It forwards the hook's stdin to the warden daemon over loopback TCP and
// prints back exactly what the daemon says to print. Cold start is ~1-3ms vs
// ~130ms for a node hook, so warden can screen every single tool call without
// any felt latency.
//
// It is a pure byte pipe: it parses none of the hook payload, holds no policy,
// runs no classifier. All of that lives in the daemon, the single source of
// truth.
//
// Fail SAFE, not open: if the daemon can't be reached (not running, timeout,
// short read), it falls back to the Node hook (src/cc-hook.mjs), which screens
// in-process — slower, but it still screens. Only if that fallback is also
// unavailable does it fail open (exit 0, no output) so warden can never brick
// your tooling. The fast ~2ms path is unchanged; the fallback is a cold path
// that runs only when the daemon is down.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// Dial fails fast (daemon down -> fall back quickly). The read deadline is much
// longer because a daemon with the LLM judge tier enabled may take a couple
// seconds to answer a gray-zone command — we must WAIT for that verdict, not
// time out and fall back to the no-judge path. Override with WARDEN_READ_MS.
const dialTimeout = 1500 * time.Millisecond

func readTimeout() time.Duration {
	if v := os.Getenv("WARDEN_READ_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Millisecond
		}
	}
	return 12 * time.Second
}

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

// tryDaemon forwards `<payload>\n` to the loopback daemon and returns the bytes
// before the first newline (the exact stdout the hook should emit; may be
// empty for allow/defer). ok is true only if a full line came back — so an
// empty allow is a success, but an unreachable daemon is not.
func tryDaemon(payload []byte) (out []byte, ok bool) {
	raw, err := os.ReadFile(infoPath())
	if err != nil {
		return nil, false
	}
	var info struct {
		Port int `json:"port"`
	}
	if json.Unmarshal(raw, &info) != nil || info.Port <= 0 {
		return nil, false
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Port)), dialTimeout)
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(readTimeout())) // long: judge may think for seconds
	if _, err := conn.Write(append(payload, '\n')); err != nil {
		return nil, false
	}
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 512)
	for {
		n, rerr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if i := bytes.IndexByte(buf, '\n'); i >= 0 {
				return buf[:i], true
			}
		}
		if rerr != nil {
			return nil, false
		}
	}
}

// fallbackNode runs the Node hook with payload on stdin, wiring its stdout/exit
// straight through. Returns false if the hook can't be located or launched, so
// the caller can fail open as a last resort.
func fallbackNode(payload []byte) bool {
	hook := os.Getenv("WARDEN_FALLBACK_HOOK")
	if hook == "" {
		exe, err := os.Executable()
		if err != nil {
			return false
		}
		hook = filepath.Join(filepath.Dir(exe), "..", "src", "cc-hook.mjs")
	}
	if _, err := os.Stat(hook); err != nil {
		return false
	}
	node := os.Getenv("WARDEN_NODE")
	if node == "" {
		node = "node"
	}
	cmd := exec.Command(node, hook)
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return false
	}
	os.Exit(cmd.ProcessState.ExitCode()) // propagate the node hook's exit (always 0)
	return true
}

func main() {
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(0) // fail-open
	}
	payload := bytes.TrimRight(in, " \t\r\n")
	if len(payload) == 0 {
		os.Exit(0)
	}

	// Hot path: the daemon (~2ms). deny/ask -> JSON; allow/defer -> empty.
	if out, ok := tryDaemon(payload); ok {
		_, _ = os.Stdout.Write(out)
		os.Exit(0)
	}
	// Daemon unreachable -> fall back to the Node hook (still screens).
	fallbackNode(payload)
	os.Exit(0) // fallback unavailable -> fail open (never block tooling)
}
