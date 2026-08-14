# Root-review authoring tools

The root-review MCP tools are a thin writer and observer for the existing
per-agent root-review surface. They do not create a viewer, root shell, socket,
daemon, database, queue, broker job, or execution authority.

The existing assignment binds the current server-agent tmux pane to exactly one
request file and one root transcript. The tools discover that assignment from
the MCP process's `TMUX_PANE`; callers cannot provide an agent name or path.

## Calls

`root_review_publish` accepts one human-readable purpose and one prevalidated
command of at most 32 KiB. Single-line commands use the existing `command=`
form; multiline commands use the viewer's existing `COMMAND_BEGIN` / `COMMAND_END`
form so the entire executable body remains visible and copyable. It writes the
viewer-compatible request atomically and
returns the exact same full command together with its UTF-8 byte count and
digest, in addition to the opaque handle, state, and request digest. The command
must remain fully visible in the existing root-review viewer; agents must not
replace it with an opaque command-copy-file or digest-checking wrapper merely to
make copying easier. An existing pending card is not overwritten. Each
publication includes a caller-inaccessible random card generation id, so an old
handle cannot match republished identical text.
After its transcript has appended, the same operation
may publish the next card by providing `previous_handle`.

`root_review_wait` accepts only the opaque handle and bounded wait controls. It
returns whether the transcript is unchanged or appended, plus byte counts and
digests. It never returns the command or transcript content and never clears the
card.

`root_review_resolve` accepts only an observed handle and atomically writes the
canonical `NO_PENDING_ROOT_COMMAND` request. It refuses unchanged transcripts,
stale handles, changed assignments, irregular files, unsafe ownership or modes,
and replaced transcript identities.

Three calls are intentional. The existing interactive transcript has no durable
per-command completion/exit-code envelope. A byte append alone cannot prove that
the exact command completed successfully, so `wait` must not auto-clear. The
preparing agent reads the existing transcript through the already accepted
surface, verifies the result, then calls `resolve` or publishes the next card.

The root tmux socket and root pane remain user-only. These tools neither import
subprocess/socket modules nor contain a root tmux control path.
