"""Writes a hostile image filesystem as a tar stream, like `crane export` would.
Usage: python3 -I tests/hostile_tar.py OUT.tar VULNERABLE-NODE-BINARY [--no-dotdot]

Next to a real vulnerable node binary it holds entries that try to write
outside the directory the scanner unpacks into: through a relative and an
absolute symlink, a hard link, and a "../" name, plus a name with a tab that
tries to hide the vulnerable binary. Every escape writes a file named pwned-*.
--no-dotdot leaves out the "../" names (crane refuses whole layers with them).
"""
import io
import sys
import tarfile

out, node, dotdot = sys.argv[1], sys.argv[2], "--no-dotdot" not in sys.argv[3:]
PATCHED = b"timedownlifeleftback\0_ERROR_FORMAT_EXUBERANT_NIBBLE\0_ERROR_FORMAT_BLOCK_SWITCH\0"


def add_file(t, name, data, mode=0o644):
    i = tarfile.TarInfo(name)
    i.size, i.mode = len(data), mode
    t.addfile(i, io.BytesIO(data))


def add_link(t, name, target, kind=tarfile.SYMTYPE):
    i = tarfile.TarInfo(name)
    i.type, i.linkname = kind, target
    t.addfile(i)


with open(node, "rb") as fh:
    node_bin = fh.read()
with tarfile.open(out, "w", format=tarfile.GNU_FORMAT) as t:
    add_file(t, "usr/local/bin/node", node_bin, 0o755)
    add_file(t, "usr/local/bin/node\t.node", PATCHED, 0o755)
    add_link(t, "esc-rel", "../../../../../../../../../../tmp")
    add_file(t, "esc-rel/pwned-symlink-rel", b"x\n")
    add_link(t, "esc-abs", "/tmp")
    add_file(t, "esc-abs/pwned-symlink-abs", b"x\n")
    add_link(t, "hard", "../../../../../../../../../../etc/passwd", tarfile.LNKTYPE)
    if dotdot:
        add_file(t, "../pwned-dotdot", b"x\n")
        add_file(t, "../../../../../../../../../../tmp/pwned-dotdot-tmp", b"x\n")
