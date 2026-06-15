# warden-fast — native PreToolUse hook client

A tiny compiled client that lets warden screen **every** Claude Code tool call
with no felt latency.

## Why

A Node hook pays Node's startup + ESM module-load cost on every single tool
call. Measured on this machine (`node native/bench.mjs`):

```
node cc-hook.mjs : median   78.0  min   69.4  max   84.7 ms
warden-fast.exe  : median   18.3  min   15.6  max   21.3 ms
speedup (median) : 4.3x   (saves ~60ms per tool call)
```

The daemon already loads the classifier + policy once and answers over a socket
— but a *Node* client still pays Node startup to ask it. `warden-fast` is that
client, compiled: it cold-starts in ~2ms and is a pure byte pipe.

## How it works

```
Claude Code ──stdin(JSON)──▶ warden-fast ──TCP 127.0.0.1──▶ warden daemon
                                  ▲                              │
                                  └──────── stdout bytes ────────┘
```

1. The daemon (`warden serve`) writes its loopback port to `~/.warden/daemon.json` (0600).
2. `warden-fast` reads that port, forwards the hook's stdin verbatim, reads back
   one line, and prints it — that line is **exactly** the bytes the hook should
   emit (a `hookSpecificOutput` deny/ask JSON, or empty for allow/defer).

It parses none of the payload, holds no policy, runs no classifier. **All logic
stays in the daemon (JS) — the single source of truth.** The binary is dumb on
purpose: nothing to keep in sync, nothing to drift.

**Fail-open by design.** No daemon, timeout, or short read → exit 0 with no
output, so Claude Code proceeds. warden can never brick your tooling. (If you
want screening when the daemon is down, register the Node hook `warden-hook`
instead — it classifies in-process as a fallback. `warden-fast` is the
daemon-paired speed mode.)

## Security model

The fast-hook listener is bound to **127.0.0.1 only** — never exposed off-box.
Any process running **as the same user** can connect, but that is already inside
warden's trust boundary: such a process could edit `~/.warden/config.json`,
unregister the hook, or kill the daemon regardless. So loopback-only is the real
control; no shared token is used (it would add fragility, not security, at this
boundary). This matches the existing named-pipe transport.

## Build

Requires Go ≥ 1.21. Zero external dependencies (stdlib only) → a single static
binary, no libc, no runtime.

```sh
cd native
# this platform
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o warden-fast .
# cross-compile for the fleet
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o warden-fast-linux-amd64 .
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o warden-fast.exe .
```

Verify against a live daemon (spawns the binary exactly as Claude Code does):

```sh
node native/smoke.mjs      # correctness: deny / defer / fail-open
node native/bench.mjs 30   # latency vs the node hook
```

## Use it as the hook

1. Run the daemon (ideally as a service so it's always up):
   ```sh
   warden serve              # listens on the socket + loopback fast-hook
   ```
2. Point your Claude Code PreToolUse hook command at the binary instead of
   `warden-hook`:
   ```json
   { "type": "command", "command": "C:\\path\\to\\warden\\native\\warden-fast.exe", "timeout": 5 }
   ```

That's it — same deny/ask/allow behavior, ~60ms cheaper per call.
