Purpose
-
This folder provides a small dynamic library that interposes common file-opening APIs and logs paths that look like CEROD filenames (contain ":cerod:", the activation key, or "KeyKey.db").

Files
-
- `cerod_interpose.c` — interpose library source.
- `build_interpose.sh` — builds `libcerod_interpose.dylib` using clang.
- `run_cerod_inject.sh` — helper to launch the target executable with the library injected via `DYLD_INSERT_LIBRARIES` and show the initial log.

Quick steps
-
1. Build: `./scripts/build_interpose.sh`
2. Run KeyKey under injection (preferably in an isolated VM/test account):

```bash
./scripts/run_cerod_inject.sh /path/to/KeyKeyExecutable [args...]
```

3. Watch log: `tail -f /tmp/cerod_trace.log`

Notes and safety
-
- Prefer running the IME/binary in an isolated VM or secondary user session to avoid interacting with your host IME and to avoid the freeze issues previously observed when attaching debuggers.
- If the UI/App is launched by macOS services, you may need to find and launch the actual executable inside the `.app` bundle.
- After a successful run, `/tmp/cerod_trace.log` will contain one line per matched call; it includes timestamp, PID, function name, path, and return address.
- If injection is blocked (SIP / notarization / code-signing), run the executable directly in the VM (not via launchservices) or use an isolated test build when possible.

Next steps
-
- If a CEROD filename is recorded, use it to inform chunk ordering and reassembly heuristics.
- If no filenames appear, extend the interposer to capture additional calls (e.g., low-level syscalls) or use the provided LLDB script `scripts/cerod_breakpoint.lldb` in an isolated VM to set breakpoints at the discovered caller and open-wrapper addresses and print string args.

LLDB usage example
-
Run in an isolated VM or secondary user account to avoid freezing the host IME:

```bash
# start under lldb and source the script
lldb -- /path/to/KeyKeyExecutable
(lldb) command source scripts/cerod_breakpoint.lldb
(lldb) run
```

Breakpoints in the script will print candidate filename strings and backtrace when hit, then continue execution.

