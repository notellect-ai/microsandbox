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
    # A pending read is cancelled before each write and its bytes dropped.
    "cancel_drops_read": ("windows::tests::large_streams_both_ways_at_once_arrive_whole",
        "        if !outgoing.is_empty() {\n            match write_all(",
        "        if !outgoing.is_empty() {\n            read.cancel();\n            match write_all("),
}
name, path = sys.argv[1], sys.argv[2]
test, old, new = MUTANTS[name]
text = open(path, encoding="utf-8").read()
assert text.count(old) == 1, (name, text.count(old))
open(path, "w", encoding="utf-8").write(text.replace(old, new))
print(f"TEST={test}")
