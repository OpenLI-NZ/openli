#!/usr/bin/env python3
"""Test collector Cisco functions with stub external APIs (GPL-3.0-or-later).

Requires Python 3 and a C11 compiler with pthread support. No PCAP, libtrace,
third-party Python module or configured OpenLI build is required. See README.md
for the distinction between this harness and an integrated collector test.
"""
import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]


def function(source, name):
    """Extract a named definition; fail explicitly if the source layout changes."""
    match = re.search(r"^\S[^\n]*\b" + re.escape(name) + r"\(", source, re.M)
    if match is None:
        raise ValueError("cannot find function definition: " + name)
    brace = source.index("{", match.start())
    depth, end = 1, brace + 1
    while depth:
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
        end += 1
    return source[match.start():end] + "\n"


def run(baseline, sanitize):
    path = "src/collector/cisco_parser.c"
    if baseline:
        cisco = subprocess.check_output(
            ["git", "show", baseline + ":" + path], cwd=ROOT, text=True)
    else:
        cisco = (ROOT / path).read_text()
    collector = (ROOT / "src/collector/collector.c").read_text()
    source = cisco[cisco.index("typedef struct ciscomirror_hdr"):
                   cisco.index("/** Converts a Cisco")]
    if not baseline:
        source += function(cisco, "generate_cc_from_cisco_payload")
    source += function(cisco, "generate_cc_from_cisco")
    source += function((ROOT / "src/coreserver.c").read_text(),
                       "match_packet_to_coreserver")
    if not baseline:
        for name in ("cisco_fragment_destination", "cisco_fragment_context",
                     "process_cisco_fragment"):
            source += function(collector, name)
        # Check the real callback invokes the tested helper before worker-local
        # fragment port recovery and cannot decode raw fragments as Cisco CC.
        if collector.index("process_cisco_fragment(trace, t, inp") >= collector.index(
                "pinfo.fragoff = trace_get_fragment_offset"):
            raise ValueError("Cisco assembly must precede fragment port recovery")
        if "glob->ciscomirrors && !(offset & 0x3fff)" not in collector:
            raise ValueError("raw fragments must bypass Cisco decoding")
    template = (ROOT / "src/tests/pcli/harness.c.in").read_text()
    with tempfile.TemporaryDirectory(prefix="openli-pcli-") as directory:
        source_file, executable = Path(directory) / "test.c", Path(directory) / "test"
        source_file.write_text(template.replace("@SOURCE@", source))
        command = shlex.split(os.environ.get("CC", "cc")) + [
            "-std=c11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
            "-Wno-unused-parameter", "-Wno-unused-function", "-Wno-unused-variable",
            "-pthread", "-I" + str(ROOT / "src/collector")]
        if baseline:
            command += ["-DBASELINE"]
        if sanitize:
            command += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        if not baseline:
            cache_test = Path(directory) / "test_cache"
            subprocess.run(command + [str(ROOT / "src/tests/test_cisco_reassembly.c"),
                                      str(ROOT / "src/collector/cisco_reassembly.c"),
                                      "-o", str(cache_test)], check=True)
            subprocess.run([str(cache_test)], check=True)
        subprocess.run(command + [str(source_file),
                                  str(ROOT / "src/collector/cisco_reassembly.c"),
                                  "-o", str(executable)], check=True)
        result = subprocess.run([str(executable)], check=False)
        if baseline:
            if result.returncode != 1:
                raise RuntimeError("baseline did not reproduce expected failure")
            print("PASS: expected baseline failure reproduced")
        else:
            result.check_returncode()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", metavar="REVISION",
                        help="optional original parser revision; requires its Git object")
    parser.add_argument("--sanitize", action="store_true", help="enable ASan and UBSan")
    args = parser.parse_args()
    run(args.baseline, args.sanitize)
