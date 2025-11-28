"""CLI tool for extracting IL2CPP global-metadata.dat from a Windows memory dump.

This module provides functionality to extract IL2CPP global-metadata.dat from
Windows memory dumps. It can work with existing .dmp files or automatically
create dumps from running processes.

Features:
    * Works on an existing .dmp file created via Task Manager or other tools.
    * Optional auto-dump support for a running process (Windows only).
    * Auto-detection of BPSR.exe or BPSR_STEAM.exe processes.
    * Logs progress and errors with standard Python logging.

Original implementation by @rushkii using analysis provided by @dmlgzs.
This refactor focuses on PEP 8 / PEP 257 compliance, logging, and CLI ergonomics.
"""

from __future__ import annotations

import argparse
import logging
import os
import struct
from collections.abc import Iterable
from pathlib import Path

try:
    import ctypes
    import ctypes.wintypes as wt
except ImportError:  # pragma: no cover - non-Windows
    ctypes = None  # type: ignore[assignment]
    wt = None  # type: ignore[assignment]

LOGGER = logging.getLogger(__name__)

# IL2CPP metadata header magic sequence (little-endian 0xFAB11BAF).
# This 4-byte signature identifies the start of IL2CPP global-metadata.dat
# structures within memory dumps. Used to locate metadata headers in raw dump data.
IL2CPP_MAGIC = b"\xaf\x1b\xb1\xfa"


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Optional iterable of argument strings. If omitted, sys.argv[1:] is used.

    Returns:
        Parsed arguments as an argparse.Namespace object.
    """
    parser = argparse.ArgumentParser(
        description="Extract IL2CPP global-metadata.dat from a memory dump."
    )
    parser.add_argument(
        "dumpfile",
        nargs="?",
        type=Path,
        help="Path to an existing .dmp file. "
        "If omitted, --process is required to create one.",
    )
    parser.add_argument(
        "outfile",
        nargs="?",
        type=Path,
        help="Output metadata path (default: ./global-metadata.dat).",
    )
    parser.add_argument(
        "--process",
        "-p",
        default=None,
        help="Optional process image name to dump (e.g. BPSR.exe). "
        "Requires Windows and debugging privileges.",
    )
    parser.add_argument(
        "--dump-out",
        "-d",
        type=Path,
        default=None,
        help="Dump file to create when --process is used. "
        "Defaults to ./<process>.dmp.",
    )
    parser.add_argument(
        "--delete-dump",
        action="store_true",
        help="Delete the dump file after successful extraction (default: keep it).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase logging verbosity (-v, -vv).",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def configure_logging(verbosity: int) -> None:
    """Configure global logging based on verbosity flags.

    Args:
        verbosity: Verbosity level (0=WARNING, 1=INFO, 2+=DEBUG).
    """
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def extract_metadata(dump_path: Path, out_path: Path) -> None:
    """Extract the IL2CPP global-metadata.dat chunk from a dump file.

    Args:
        dump_path: Path to the memory dump (.dmp) file.
        out_path: Output path for the extracted metadata file.

    Raises:
        FileNotFoundError: If the dump file does not exist.
        RuntimeError: If the IL2CPP magic sequence cannot be found or metadata
            size cannot be inferred.
    """
    if not dump_path.is_file():
        raise FileNotFoundError(dump_path)

    LOGGER.info("Loading dump file: %s", dump_path)
    data = dump_path.read_bytes()

    # Search for IL2CPP metadata magic sequence to locate the metadata header
    # within the potentially large memory dump file.
    idx = data.find(IL2CPP_MAGIC)
    if idx == -1:
        raise RuntimeError("IL2CPP metadata magic not found in dump")

    LOGGER.info("Found metadata magic at offset 0x%X", idx)

    # Helper function to read 32-bit unsigned integers in little-endian format.
    # IL2CPP metadata uses little-endian byte order, matching Windows/x86 conventions.
    def read_u32(offset: int) -> int:
        return int(struct.unpack_from("<I", data, offset)[0])

    header_off = idx
    sanity = read_u32(header_off)
    version = read_u32(header_off + 4)
    LOGGER.debug("Metadata sanity: 0x%X", sanity)
    LOGGER.info("Metadata version: %d", version)

    # Scan the first 256 bytes (0x100) of the metadata header in 4-byte increments.
    # The IL2CPP metadata header contains offset values pointing to various metadata
    # sections. Valid offsets are positive values less than 0x0FFFFFFF (to exclude
    # sentinel values and invalid pointers).
    offsets: list[int] = []
    for i in range(0, 0x100, 4):
        val = read_u32(header_off + i)
        if 0 < val < 0x0FFFFFFF:
            offsets.append(val)

    if not offsets:
        raise RuntimeError("Could not infer metadata size from header offsets")

    # Estimate metadata size by finding the maximum offset and adding 0x1000 bytes
    # of padding. This ensures we capture the complete metadata structure even if
    # the size calculation is slightly conservative.
    metadata_size = max(offsets) + 0x1000
    LOGGER.info(
        "Estimated metadata size: %d bytes (~%.1f KiB)",
        metadata_size,
        metadata_size / 1024.0,
    )

    end = idx + metadata_size
    chunk = data[idx:end]

    out_path.write_bytes(chunk)
    LOGGER.info("Extracted metadata written to: %s", out_path)


# ---- Windows dump creation helpers (Windows-only functionality) -------------


def is_windows() -> bool:
    """Check if running on Windows.

    Returns:
        True if running on Windows, False otherwise.
    """
    return os.name == "nt"


def find_bpsr_process() -> str | None:
    """Auto-detect a running BPSR process.

    Tries BPSR.exe first, then falls back to BPSR_STEAM.exe if not found.

    Returns:
        Process name if found (e.g., "BPSR.exe"), None otherwise.

    Raises:
        RuntimeError: If not running on Windows or tasklist fails.
    """
    if not is_windows():
        return None

    # Try BPSR.exe first (standard version), then fall back to BPSR_STEAM.exe.
    # This priority order ensures the standard version is preferred when both
    # are available, which is the more common use case.
    for process_name in ("BPSR.exe", "BPSR_STEAM.exe"):
        try:
            output = os.popen(f'tasklist /FI "IMAGENAME eq {process_name}" /NH').read()
            for line in output.splitlines():
                # Use case-insensitive comparison because Windows process names
                # may appear with different casing in tasklist output, and we want
                # to match regardless of case.
                if line.upper().startswith(process_name.upper()):
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            # Validate that the second field is a valid integer PID.
                            # This ensures we found a real process entry, not a header
                            # or malformed output line.
                            int(parts[1])
                            LOGGER.info("Auto-detected process: %s", process_name)
                            return process_name
                        except ValueError:
                            pass
        except OSError:
            continue

    return None


def create_dump_for_process(process_name: str, dump_path: Path) -> bool:
    """Create a full memory dump for a running process (Windows only).

    If the dump file already exists, it will be reused instead of creating a new one.

    Args:
        process_name: Executable image name, e.g. "BPSR.exe".
        dump_path: Destination path for the dump file.

    Returns:
        True if a new dump file was created, False if an existing file was reused.

    Raises:
        RuntimeError: If not running on Windows, the process cannot be found,
            or the dump operation fails.
    """
    if not is_windows() or ctypes is None or wt is None:
        raise RuntimeError("Process dumping is only supported on Windows.")

    # Reuse existing dump file if present to avoid expensive process memory dump
    # operation. This allows re-running extraction without recreating large dump
    # files, significantly improving performance for iterative development.
    if dump_path.exists():
        LOGGER.info("Dump file already exists at %s, reusing existing file", dump_path)
        return False

    # Use tasklist command to find the process PID, avoiding direct Windows API
    # calls for process enumeration which would require additional privileges.
    try:
        output = os.popen(f'tasklist /FI "IMAGENAME eq {process_name}" /NH').read()
    except OSError as exc:  # pragma: no cover
        raise RuntimeError(f"Failed to run tasklist: {exc}") from exc

    pid = None
    for line in output.splitlines():
        if line.upper().startswith(process_name.upper()):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    pid = int(parts[1])
                except ValueError:
                    pass
            break

    if pid is None:
        raise RuntimeError(f"Process {process_name!r} not found.")

    LOGGER.info("Found %s with PID %d", process_name, pid)

    # Windows API constants for process access and file operations.
    # PROCESS_QUERY_INFORMATION: Required to query process information.
    # PROCESS_VM_READ: Required to read process memory for the dump.
    # GENERIC_WRITE: File access right for writing the dump file.
    # CREATE_ALWAYS: Overwrite existing file if present.
    # FILE_ATTRIBUTE_NORMAL: Standard file attributes.
    # MiniDumpWithFullMemory: Dump type flag to include all process memory.
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    GENERIC_WRITE = 0x40000000
    CREATE_ALWAYS = 2
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    MiniDumpWithFullMemory = 0x00000002

    # Load Windows DLLs for process and file operations.
    # use_last_error=True enables proper Windows error code retrieval.
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)

    # Configure Windows API function signatures for type safety.
    # ctypes requires explicit type definitions to properly marshal arguments
    # and return values between Python and Windows API calls. Without these,
    # the API calls would fail or produce incorrect results.
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    open_process.restype = wt.HANDLE

    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wt.LPCWSTR,
        wt.DWORD,
        wt.DWORD,
        wt.LPVOID,
        wt.DWORD,
        wt.DWORD,
        wt.HANDLE,
    ]
    create_file.restype = wt.HANDLE

    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wt.HANDLE]
    close_handle.restype = wt.BOOL

    mini_dump_write_dump = dbghelp.MiniDumpWriteDump
    mini_dump_write_dump.argtypes = [
        wt.HANDLE,
        wt.DWORD,
        wt.HANDLE,
        wt.ULONG,
        wt.LPVOID,
        wt.LPVOID,
        wt.LPVOID,
    ]
    mini_dump_write_dump.restype = wt.BOOL

    LOGGER.info("Creating dump at %s", dump_path)
    h_process = open_process(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h_process:
        raise RuntimeError(f"OpenProcess failed (error {ctypes.get_last_error()})")

    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    h_file = create_file(
        str(dump_path),
        GENERIC_WRITE,
        0,
        None,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if h_file == INVALID_HANDLE_VALUE:
        close_handle(h_process)
        raise RuntimeError(f"CreateFileW failed (error {ctypes.get_last_error()})")

    # Create full memory dump including all process memory.
    # MiniDumpWithFullMemory is required to capture the IL2CPP metadata which
    # may be located anywhere in the process address space.
    ok = mini_dump_write_dump(
        h_process,
        pid,
        h_file,
        MiniDumpWithFullMemory,
        None,
        None,
        None,
    )

    # Always close Windows handles to prevent resource leaks.
    # Failing to close handles can lead to handle exhaustion and system instability.
    close_handle(h_file)
    close_handle(h_process)

    if not ok:
        raise RuntimeError(
            f"MiniDumpWriteDump failed (error {ctypes.get_last_error()})"
        )

    LOGGER.info("Dump created successfully.")
    return True


# ---- Main CLI entrypoint -----------------------------------------------------


def main(argv: Iterable[str] | None = None) -> int:
    """Entry point for the CLI.

    Args:
        argv: Optional command-line arguments. If omitted, sys.argv[1:] is used.

    Returns:
        0 on success, 1 on error.
    """
    args = parse_args(argv)
    configure_logging(args.verbose)

    dump_path: Path | None = args.dumpfile
    out_path: Path = args.outfile or Path("global-metadata.dat")
    process_name: str | None = args.process
    dump_was_auto_created = False

    try:
        # Auto-detect BPSR process if neither dumpfile nor explicit process provided.
        # This fallback strategy improves usability by allowing the tool to work
        # without requiring users to manually specify process names or dump files.
        if dump_path is None and process_name is None:
            process_name = find_bpsr_process()
            if process_name is None:
                raise RuntimeError(
                    "No dumpfile provided and no BPSR process found. "
                    "Please provide a dumpfile or ensure BPSR.exe or "
                    "BPSR_STEAM.exe is running."
                )

        if dump_path is None and process_name:
            # Auto-dump mode: create memory dump from running process.
            default_dump = args.dump_out or Path(process_name).with_suffix(".dmp")
            dump_was_auto_created = create_dump_for_process(process_name, default_dump)
            dump_path = default_dump
        elif dump_path is None:
            raise RuntimeError(
                "You must provide either a dumpfile argument or --process."
            )

        extract_metadata(dump_path, out_path)

        # Delete dump file only if it was newly created in this run and --delete-dump
        # is specified. Dump files are kept by default to allow re-running extraction
        # without recreating large dump files, which can be several gigabytes in size.
        if dump_was_auto_created and args.delete_dump:
            try:
                dump_path.unlink()
                LOGGER.info("Deleted dump file %s", dump_path)
            except OSError as exc:
                LOGGER.warning("Could not delete dump file %s: %s", dump_path, exc)

    except (FileNotFoundError, RuntimeError, OSError) as exc:
        LOGGER.error("%s", exc)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
