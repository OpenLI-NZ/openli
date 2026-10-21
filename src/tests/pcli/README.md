# Cisco mirror fragment regression tests

The tests generate packets in memory. They need no PCAP, network interface,
root privileges, third-party Python modules, installed libtrace headers, or
configured OpenLI build. Run them from the repository root, using a C11
compiler with pthread support and Python 3:

```sh
python3 src/tests/pcli/run.py
```

`CC` can select the compiler (including a compiler wrapper, e.g. `CC='ccache cc'`).
The script compiles and runs both the direct cache test and the collector
harness in a temporary directory, then removes the generated files on exit. The normal test does not invoke Git or need any
historical revision. It also works from an unpacked source distribution.

The cache itself is compiled directly into a separate C test, also included in
`make check` when OpenLI is configured with its normal dependencies:

```sh
cc -std=c11 -Wall -Wextra -Werror -pthread \
    src/tests/test_cisco_reassembly.c src/collector/cisco_reassembly.c \
    -o /tmp/test_cisco_reassembly
/tmp/test_cisco_reassembly
```

This test covers in-order and reordered two/three-part assembly, identical
fragment duplicates, completion replay suppression, conflicting and partial
overlaps, invalid/truncated lengths, fragment alignment/offsets, UDP lengths,
missing fragments, expiry, context/input isolation, active/retired/fragment
limits and concurrent callers. Every completed datagram is checked byte for
byte, including its selected timestamp. Assertions remain enabled even if a
build supplies `-DNDEBUG`.

The Python harness additionally compiles functions extracted from the current
collector and Cisco parser sources with stubs for libtrace, hash storage,
provisioning and CC export. This exercises the real destination/context match,
core-server matcher, unfragmented decoder and vendor CC path, and early Cisco
fragment handler. It verifies vendor IDs and inner bytes across different
workers, wrong destinations/ports, unknown IDs, concurrent mappings, inner
header errors/padding, the RADIUS stripping branch, and VLAN/QinQ isolation
when either tag differs. Source checks verify that the callback calls the
handler before legacy worker-local port recovery and excludes raw outer
fragments from Cisco decoding.

This source-extraction harness is a focused regression test, not a complete
collector translation-unit build or a libtrace/ETSI integration test. The
function extraction assumes the current C source layout; a future function
rename/layout change may require updating the harness. Stub provisioning,
filters and export do not establish real service or backend behavior.

## Optional checks

For the original regression, the harness can use the Cisco parser from an
explicit **pre-fix** Git revision while keeping the synthetic tests and stubs:

```sh
python3 src/tests/pcli/run.py --baseline PRE_FIX_REVISION
```

This optional check requires that Git object to exist locally; it never fetches
anything. It must report the expected failure: the first fragment exports
1100 bytes instead of the expected 1500-byte inner packet. Its exit status is
zero only when that specific regression is reproduced. No baseline revision
is hard-coded into the test.

If the compiler supports ASan and UBSan:

```sh
python3 src/tests/pcli/run.py --sanitize
cc -std=c11 -Wall -Wextra -Werror -pthread -g -O1 \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    src/tests/test_cisco_reassembly.c src/collector/cisco_reassembly.c \
    -o /tmp/test_cisco_reassembly_sanitize
/tmp/test_cisco_reassembly_sanitize
```

Some tracing/sandbox environments cannot run LeakSanitizer. If necessary use
`ASAN_OPTIONS=detect_leaks=0` for ASan/UBSan checks there, and report leak
checking as unavailable rather than passed.

## Collector/backend validation

In an isolated setup, compare the original and patched collector with an active
synthetic vendor-ID intercept, `cisconoradius: yes`, and a matching top-level
`ciscomirrors` destination. Confirm exactly one intact inner packet per
completed outer datagram, correct intercept/CIN, no partial/duplicate CC, and
unchanged unfragmented output. Preserve inner IP fragmentation and trailing
mirror padding. Repeat with multiple workers and simultaneous vendor IDs,
missing/overlapping groups, VLAN and QinQ, input restart and configuration
reload. Validate other mirror formats and ordinary traffic with local existing
regression fixtures.

For live `xdp:` and `ring:` input, replay from a different physical TX port into
the monitored RX port. Local TX on the monitored interface does not establish
XDP RX delivery. Check tag visibility after NIC offloads and retain all outer
fragments in any filters: UDP-port-only filters may exclude noninitial
fragments. This patch cannot recover fragments lost before the callback.
