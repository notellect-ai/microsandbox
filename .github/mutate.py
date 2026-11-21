import sys
MUTANTS = {
    # The relay keeps reading Host bytes with the guest buffer full.
    "read_uncapped": ("windows::tests::a_host_flood_stops_at_the_guest_buffer_and_then_arrives_whole",
        "                MAX_BUFFERED_BYTES.saturating_sub(state.incoming.len())\n",
        "                IO_CHUNK_SIZE\n"),
    # Guest writes are accepted past the buffer.
    "write_uncapped": ("windows::tests::guest_writes_stop_at_the_buffer_while_the_host_reads_nothing_and_then_arrive_whole",
        "            .min(MAX_BUFFERED_BYTES.saturating_sub(state.outgoing.len()));",
        ";"),
    # A write shutdown discards bytes already queued.
    "write_shutdown_drops_queue": ("windows::tests::a_guest_write_shutdown_mid_stream_still_delivers_what_was_queued",
        "            VsockShutdown::Write => state.write_shutdown = true,",
        "            VsockShutdown::Write => {\n                state.write_shutdown = true;\n                state.outgoing.clear();\n            }"),
    # A full shutdown leaves the worker writing to the Host.
    "full_shutdown_keeps_writing": ("windows::tests::a_guest_full_shutdown_mid_write_releases_the_pipe",
        "                state.write_shutdown = true;\n                state.terminate = true;\n",
        "                state.write_shutdown = true;\n"),
    # A Host close is not reported to the guest end.
    "close_ignored": ("windows::tests::a_host_disconnect_mid_write_ends_the_guest_stream",
        "    fn close(&self) {\n",
        "    fn close(&self) {\n        return;\n        #[allow(unreachable_code)]\n"),
    # The write's OVERLAPPED signals the read's event, so a completion in one
    # direction is taken for a completion in the other.
    "shared_event": ("windows::tests::large_streams_both_ways_at_once_arrive_whole",
        [("    pump(&mut read, &mut write, &shared);\n",
          "    let own = std::mem::replace(&mut write.event, Event(read.event.0));\n    drop(own);\n    pump(&mut read, &mut write, &shared);\n"),
         ("        let _ = shared.notifier.notify();\n    }\n}\n\n/// Move bytes both ways",
          "        let _ = shared.notifier.notify();\n    }\n    // Do not close the read's event twice.\n    std::mem::forget(std::mem::replace(&mut write.event, Event::new(true).unwrap()));\n}\n\n/// Move bytes both ways")]),
}
name, path = sys.argv[1], sys.argv[2]
test, *edits = MUTANTS[name]
if len(edits) == 2:
    edits = [tuple(edits)]
else:
    edits = edits[0]
text = open(path, encoding="utf-8").read()
for old, new in edits:
    assert text.count(old) == 1, (name, old, text.count(old))
    text = text.replace(old, new)
open(path, "w", encoding="utf-8").write(text)
print(f"TEST={test}")
