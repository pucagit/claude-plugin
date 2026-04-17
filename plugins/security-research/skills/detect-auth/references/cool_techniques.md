# Cool Techniques — Auth & Access Control Detection
<!-- Techniques are added by /security-research:capture-technique -->

### Enumerate All Entry Points to a Protected Capability (learned 2026-04-16)
**When to apply**: A named kill-switch config flag (e.g. `enable-debug-command`, `enable-module-command`, `allow-*`) claims to disable a dangerous capability. Any C/Go/Java server where related commands are spread across multiple source files or dispatched by name.
**Technique**: Grep for every reader of the flag (`server.enable_X`, `cfg.allow_X`). Then grep for the *capability itself* — every command, subcommand, or handler that exposes equivalent functionality (Lua debugger, module loading, raw memory ops, etc.) — and diff the two lists. A handler that provides the capability but does not check the flag is an auth bypass. Don't trust the flag name; trust the call graph.
**Example**: Redis `enable-debug-command` was enforced in the main command dispatcher for `debugCommand` but the `SCRIPT DEBUG` subcommand in `eval.c` — which grants identical Lua debugger access — had zero check. Bypass enabled a full memory-corruption RCE chain against default configs.

