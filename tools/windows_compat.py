"""
Windows compatibility layer for Hermes Agent.

Provides cross-platform abstractions for:
- Process spawning and termination
- IPC (Named Pipes on Windows, Unix Domain Sockets on Unix)
- File locking
- Signal handling
- Shell detection

Inspired by OpenClaw's windows-spawn.ts and exec.ts patterns.
"""

import os
import sys
import subprocess
import signal
import shutil
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

logger = logging.getLogger(__name__)

# Platform detection
_IS_WINDOWS = sys.platform == "win32"
_IS_POSIX = not _IS_WINDOWS


# ---------------------------------------------------------------------------
# Platform Detection
# ---------------------------------------------------------------------------

def is_windows() -> bool:
    """Check if running on Windows."""
    return _IS_WINDOWS


def is_posix() -> bool:
    """Check if running on a POSIX system (Linux/macOS)."""
    return _IS_POSIX


# ---------------------------------------------------------------------------
# Signal Compatibility
# ---------------------------------------------------------------------------

# Windows doesn't have all POSIX signals
if _IS_WINDOWS:
    SIGTERM = signal.SIGTERM
    SIGKILL = signal.SIGTERM  # Windows doesn't have SIGKILL, use SIGTERM
    SIGUSR1 = None
    SIGUSR2 = None
    SIGHUP = None
    SIGINT = signal.SIGINT
else:
    SIGTERM = signal.SIGTERM
    SIGKILL = signal.SIGKILL
    SIGUSR1 = signal.SIGUSR1
    SIGUSR2 = signal.SIGUSR2
    SIGHUP = signal.SIGHUP
    SIGINT = signal.SIGINT


def get_signal(sig_name: str) -> Optional[int]:
    """Get signal number by name, cross-platform."""
    signals = {
        "SIGTERM": SIGTERM,
        "SIGKILL": SIGKILL,
        "SIGUSR1": SIGUSR1,
        "SIGUSR2": SIGUSR2,
        "SIGHUP": SIGHUP,
        "SIGINT": SIGINT,
    }
    return signals.get(sig_name.upper())


# ---------------------------------------------------------------------------
# Process Tree Termination
# ---------------------------------------------------------------------------

def terminate_process_tree(pid: int, force: bool = False) -> bool:
    """
    Terminate a process and all its children.
    
    On Windows: Uses taskkill /T /F
    On Unix: Uses os.killpg with SIGTERM/SIGKILL
    
    Args:
        pid: Process ID to terminate
        force: If True, use force kill (SIGKILL or taskkill /F)
    
    Returns:
        True if termination was successful
    """
    if _IS_WINDOWS:
        return _terminate_windows_process_tree(pid, force)
    else:
        return _terminate_unix_process_tree(pid, force)


def _terminate_windows_process_tree(pid: int, force: bool = False) -> bool:
    """Terminate a Windows process tree using taskkill."""
    try:
        cmd = ["taskkill", "/PID", str(pid), "/T"]
        if force:
            cmd.append("/F")
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
        )
        if result.returncode == 0:
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        logger.debug(f"taskkill failed for PID {pid}: {e}")
    
    # Fallback: try os.kill
    try:
        os.kill(pid, signal.SIGTERM)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False
    
    return False


def _terminate_unix_process_tree(pid: int, force: bool = False) -> bool:
    """Terminate a Unix process tree using process groups."""
    sig = signal.SIGKILL if force else signal.SIGTERM
    
    try:
        # Try to kill the entire process group
        pgid = os.getpgid(pid)
        os.killpg(pgid, sig)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        # Fallback: kill just the process
        try:
            os.kill(pid, sig)
            return True
        except (ProcessLookupError, PermissionError):
            return False


# ---------------------------------------------------------------------------
# Windows Command Resolution
# ---------------------------------------------------------------------------

_WINDOWS_PATH_EXTENSIONS = [".exe", ".cmd", ".bat", ".com"]


def resolve_windows_executable(command: str, env: Optional[Dict[str, str]] = None) -> str:
    """
    Resolve a Windows command to its full path.
    
    On Windows, searches PATH and PATHEXT for the executable.
    On Unix, returns the command unchanged.
    
    Args:
        command: Command name or path
        env: Environment dict (uses os.environ if None)
    
    Returns:
        Full path to the executable, or the original command if not found
    """
    if not _IS_WINDOWS:
        return command
    
    # Already an absolute path
    if os.path.isabs(command):
        return command
    
    # Has path separators
    if "/" in command or "\\" in command:
        return command
    
    env = env or os.environ
    path_value = env.get("PATH", "") or env.get("Path", "")
    path_entries = [p.strip() for p in path_value.split(";") if p.strip()]
    
    # Check if command already has an extension
    ext = os.path.splitext(command)[1].lower()
    has_extension = ext in [e.lower() for e in _WINDOWS_PATH_EXTENSIONS]
    
    if has_extension:
        extensions = [""]
    else:
        path_ext = env.get("PATHEXT", ".EXE;.CMD;.BAT;.COM")
        extensions = []
        for e in path_ext.split(";"):
            e = e.strip()
            if e:
                if not e.startswith("."):
                    e = f".{e}"
                extensions.append(e)
    
    for directory in path_entries:
        for ext in extensions:
            candidate = os.path.join(directory, f"{command}{ext}")
            if os.path.isfile(candidate):
                return candidate
    
    return command


def is_batch_file(path: str) -> bool:
    """Check if a file is a Windows batch file (.cmd or .bat)."""
    if not _IS_WINDOWS:
        return False
    ext = os.path.splitext(path)[1].lower()
    return ext in (".cmd", ".bat")


def build_cmd_command_line(command: str, args: List[str]) -> str:
    """
    Build a command line string for cmd.exe /c.
    
    Handles quoting and escaping for Windows cmd.exe.
    """
    def escape_arg(arg: str) -> str:
        # Quote if contains space, tab, or quote
        if " " in arg or "\t" in arg or '"' in arg or not arg:
            # Double inner quotes
            return f'"{arg.replace(chr(34), chr(34)+chr(34))}"'
        return arg
    
    return " ".join([escape_arg(command)] + [escape_arg(a) for a in args])


# ---------------------------------------------------------------------------
# IPC: Named Pipes for Windows (replaces Unix Domain Sockets)
# ---------------------------------------------------------------------------

def create_ipc_server(name: str):
    """
    Create an IPC server.
    
    On Unix: Unix Domain Socket at /tmp/hermes_<name>.sock
    On Windows: Named Pipe at \\.\pipe\hermes_<name>
    
    Args:
        name: Unique name for the IPC endpoint
    
    Returns:
        Socket-like object (Unix socket or WindowsNamedPipeServer)
    """
    if _IS_WINDOWS:
        return WindowsNamedPipeServer(f"\\\\.\\pipe\\hermes_{name}")
    else:
        import socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock_path = f"/tmp/hermes_{name}.sock"
        # Remove stale socket if exists
        if os.path.exists(sock_path):
            os.unlink(sock_path)
        return sock


def create_ipc_client(name: str):
    """
    Create an IPC client connection.
    
    Args:
        name: Unique name for the IPC endpoint
    
    Returns:
        Socket-like object connected to the server
    """
    if _IS_WINDOWS:
        return WindowsNamedPipeClient(f"\\\\.\\pipe\\hermes_{name}")
    else:
        import socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock_path = f"/tmp/hermes_{name}.sock"
        sock.connect(sock_path)
        return sock


class WindowsNamedPipeServer:
    """
    Windows Named Pipe server (replaces Unix Domain Socket).
    
    Requires pywin32 package on Windows.
    """
    
    def __init__(self, name: str):
        self.name = name
        self._handle = None
        self._connected = False
        self._pywin32 = None
        
        if not _IS_WINDOWS:
            raise RuntimeError("WindowsNamedPipeServer is only available on Windows")
        
        try:
            import win32pipe
            import win32file
            self._win32pipe = win32pipe
            self._win32file = win32file
            self._pywin32 = True
        except ImportError:
            self._pywin32 = False
            logger.warning(
                "pywin32 not installed. Named Pipe IPC will not work. "
                "Install with: pip install pywin32"
            )
    
    def bind(self):
        """Create the named pipe (compatibility with socket API)."""
        pass  # Named pipes are created on first listen/accept
    
    def listen(self, backlog: int = 1):
        """Start listening (creates the pipe)."""
        if not self._pywin32:
            raise RuntimeError("pywin32 not available")
        
        self._handle = self._win32pipe.CreateNamedPipe(
            self.name,
            self._win32pipe.PIPE_ACCESS_DUPLEX,
            (
                self._win32pipe.PIPE_TYPE_BYTE |
                self._win32pipe.PIPE_READMODE_BYTE |
                self._win32pipe.PIPE_WAIT
            ),
            1,  # max instances
            65536,  # out buffer size
            65536,  # in buffer size
            0,  # default timeout
            None,
        )
        if self._handle == -1:
            raise OSError(f"Failed to create named pipe: {self.name}")
    
    def accept(self, timeout: float = 5.0):
        """
        Accept a client connection with a timeout.

        On Windows, ConnectNamedPipe blocks until a client connects.
        We run it in a background thread so we can honor the timeout.

        Args:
            timeout: Maximum seconds to wait for a connection (default: 5.0)

        Returns:
            (self, None) tuple on success

        Raises:
            TimeoutError: if no client connects within timeout
            RuntimeError: if pywin32 is not available
        """
        import threading

        if not self._pywin32:
            raise RuntimeError("pywin32 not available")
        if not self._handle:
            # Recreate the pipe instance if a previous accept() timed out
            # and destroyed the handle. This is safe even when a subprocess
            # has already connected — the OS routes the new pipe instance
            # to the client's waiting connection.
            self._handle = self._win32pipe.CreateNamedPipe(
                self.name,
                self._win32pipe.PIPE_ACCESS_DUPLEX,
                (
                    self._win32pipe.PIPE_TYPE_BYTE |
                    self._win32pipe.PIPE_READMODE_BYTE |
                    self._win32pipe.PIPE_WAIT
                ),
                1,  # max instances
                65536,  # out buffer size
                65536,  # in buffer size
                0,  # default timeout
                None,
            )
            if self._handle == -1:
                raise OSError(f"Failed to create named pipe: {self.name}")

        done_event = threading.Event()
        accept_error = [None]  # [Exception|None]

        def _do_connect():
            try:
                self._win32pipe.ConnectNamedPipe(self._handle, None)
                done_event.set()
            except Exception as e:
                accept_error[0] = e
                done_event.set()

        thread = threading.Thread(target=_do_connect, daemon=True)
        thread.start()

        if not done_event.wait(timeout=timeout):
            # Timeout: cancel ConnectNamedPipe by closing the handle.
            # We do NOT set _handle = None here any more — accept() now
            # recreates the handle lazily on the next call, so the polling
            # loop in _rpc_server_loop can retry without going into an
            # error loop.  The OS also cleans up the half-open pipe state.
            try:
                self._win32file.CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = None   # signal next accept() to recreate
            thread.join(timeout=0.5)
            raise TimeoutError(
                f"Named pipe accept timed out after {timeout}s. "
                f"Ensure the client process started successfully."
            )

        thread.join(timeout=0.5)
        if accept_error[0]:
            raise accept_error[0]

        self._connected = True
        return (self, None)
    
    def send(self, data: bytes) -> int:
        """Send data through the pipe."""
        if not self._pywin32 or not self._handle:
            raise RuntimeError("Named pipe not connected")

        import pywintypes
        try:
            err, written = self._win32file.WriteFile(self._handle, data)
            if err:
                raise OSError(f"WriteFile failed with error {err}")
            return written
        except pywintypes.error as e:
            # Error 109 (ERROR_BROKEN_PIPE) = other end closed the connection
            if e.winerror == 109:
                return 0
            raise

    def recv(self, bufsize: int = 4096) -> bytes:
        """Receive data from the pipe."""
        if not self._pywin32 or not self._handle:
            raise RuntimeError("Named pipe not connected")
        
        import pywintypes
        try:
            err, data = self._win32file.ReadFile(self._handle, bufsize)
            if err:
                raise OSError(f"ReadFile failed with error {err}")
            return data
        except pywintypes.error as e:
            # Error 109 (ERROR_BROKEN_PIPE) means the other end closed the pipe
            # Return empty bytes to signal end-of-stream (same as Unix recv returning 0)
            if e.winerror == 109:
                return b""
            raise
    
    def close(self):
        """Close the named pipe."""
        if self._handle:
            try:
                if self._connected:
                    self._win32pipe.DisconnectNamedPipe(self._handle)
                self._win32file.CloseHandle(self._handle)
            except Exception as e:
                logger.debug(f"Error closing named pipe: {e}")
            self._handle = None
            self._connected = False
    
    def fileno(self) -> int:
        """Return handle as file descriptor (for select compatibility)."""
        return self._handle if self._handle else -1
    
    def settimeout(self, seconds: float):
        """Set timeout (best effort - named pipes don't support this directly)."""
        pass  # Named pipes don't have native timeout support
    
    def setblocking(self, flag: bool):
        """Set blocking mode (best effort)."""
        pass


class WindowsNamedPipeClient:
    """
    Windows Named Pipe client.
    
    Requires pywin32 package on Windows.
    """
    
    def __init__(self, name: str):
        self.name = name
        self._handle = None
        self._pywin32 = False
        
        if not _IS_WINDOWS:
            raise RuntimeError("WindowsNamedPipeClient is only available on Windows")
        
        try:
            import win32file
            import pywintypes
            self._win32file = win32file
            self._pywintypes = pywintypes
            self._pywin32 = True
        except ImportError:
            logger.warning(
                "pywin32 not installed. Named Pipe IPC will not work. "
                "Install with: pip install pywin32"
            )
    
    def connect(self):
        """Connect to the named pipe."""
        if not self._pywin32:
            raise RuntimeError("pywin32 not available")
        
        import time
        for attempt in range(10):
            try:
                self._handle = self._win32file.CreateFile(
                    self.name,
                    self._win32file.GENERIC_READ | self._win32file.GENERIC_WRITE,
                    0, None,
                    self._win32file.OPEN_EXISTING,
                    0, None
                )
                if self._handle != -1:
                    return
            except self._pywintypes.error:
                pass
            time.sleep(0.1)
        
        raise ConnectionError(f"Could not connect to named pipe: {self.name}")
    
    def send(self, data: bytes) -> int:
        """Send data through the pipe."""
        if not self._pywin32 or not self._handle:
            raise RuntimeError("Named pipe not connected")

        import pywintypes
        try:
            err, written = self._win32file.WriteFile(self._handle, data)
            if err:
                raise OSError(f"WriteFile failed with error {err}")
            return written
        except pywintypes.error as e:
            # Error 109 (ERROR_BROKEN_PIPE) = other end closed the connection
            if e.winerror == 109:
                return 0
            raise

    def recv(self, bufsize: int = 4096) -> bytes:
        """Receive data from the pipe."""
        if not self._pywin32 or not self._handle:
            raise RuntimeError("Named pipe not connected")
        
        import pywintypes
        try:
            err, data = self._win32file.ReadFile(self._handle, bufsize)
            if err:
                raise OSError(f"ReadFile failed with error {err}")
            return data
        except pywintypes.error as e:
            # Error 109 (ERROR_BROKEN_PIPE) means the other end closed the pipe
            # Return empty bytes to signal end-of-stream (same as Unix recv returning 0)
            if e.winerror == 109:
                return b""
            raise
    
    def close(self):
        """Close the named pipe."""
        if self._handle:
            try:
                self._win32file.CloseHandle(self._handle)
            except Exception as e:
                logger.debug(f"Error closing named pipe: {e}")
            self._handle = None
    
    def fileno(self) -> int:
        """Return handle as file descriptor."""
        return self._handle if self._handle else -1
    
    def settimeout(self, seconds: float):
        """Set timeout (best effort)."""
        pass
    
    def setblocking(self, flag: bool):
        """Set blocking mode."""
        pass


def check_named_pipe_requirements() -> Tuple[bool, str]:
    """
    Check if named pipe requirements are met on Windows.
    
    Returns:
        (available, message) tuple
    """
    if not _IS_WINDOWS:
        return True, "Unix Domain Sockets available on POSIX"
    
    try:
        import win32pipe
        import win32file
        return True, "pywin32 installed, Named Pipes available"
    except ImportError:
        return False, "pywin32 not installed. Install with: pip install pywin32"


# ---------------------------------------------------------------------------
# File Locking
# ---------------------------------------------------------------------------

def lock_file(file_obj, exclusive: bool = True) -> bool:
    """
    Cross-platform file locking.
    
    On Windows: Uses msvcrt.locking
    On Unix: Uses fcntl.flock
    
    Args:
        file_obj: File object to lock
        exclusive: If True, acquire exclusive lock; otherwise shared lock
    
    Returns:
        True if lock was acquired
    """
    if _IS_WINDOWS:
        return _lock_file_windows(file_obj, exclusive)
    else:
        return _lock_file_unix(file_obj, exclusive)


def unlock_file(file_obj) -> bool:
    """
    Cross-platform file unlocking.
    
    Args:
        file_obj: File object to unlock
    
    Returns:
        True if lock was released
    """
    if _IS_WINDOWS:
        return _unlock_file_windows(file_obj)
    else:
        return _unlock_file_unix(file_obj)


def _lock_file_windows(file_obj, exclusive: bool = True) -> bool:
    """Windows file locking using msvcrt."""
    try:
        import msvcrt
        mode = msvcrt.LK_NBLCK if exclusive else msvcrt.LK_NBRLCK
        msvcrt.locking(file_obj.fileno(), mode, 1)
        return True
    except (OSError, ImportError):
        return False


def _unlock_file_windows(file_obj) -> bool:
    """Windows file unlocking using msvcrt."""
    try:
        import msvcrt
        msvcrt.locking(file_obj.fileno(), msvcrt.LK_UNLCK, 1)
        return True
    except (OSError, ImportError):
        return False


def _lock_file_unix(file_obj, exclusive: bool = True) -> bool:
    """Unix file locking using fcntl."""
    try:
        import fcntl
        mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        fcntl.flock(file_obj.fileno(), mode | fcntl.LOCK_NB)
        return True
    except (OSError, ImportError):
        return False


def _unlock_file_unix(file_obj) -> bool:
    """Unix file unlocking using fcntl."""
    try:
        import fcntl
        fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)
        return True
    except (OSError, ImportError):
        return False


# ---------------------------------------------------------------------------
# Windows Process Utilities
# ---------------------------------------------------------------------------

def get_windows_listening_pids(port: int) -> List[int]:
    """
    Get PIDs of processes listening on a port (Windows only).
    
    Uses PowerShell or netstat as fallback.
    
    Args:
        port: Port number to check
    
    Returns:
        List of PIDs listening on the port
    """
    if not _IS_WINDOWS:
        return []
    
    # Try PowerShell first (more reliable)
    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                f"(Get-NetTCPConnection -LocalPort {port} -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess)"
            ],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
        )
        if result.returncode == 0:
            pids = []
            for line in result.stdout.strip().split("\n"):
                try:
                    pid = int(line.strip())
                    if pid > 0:
                        pids.append(pid)
                except ValueError:
                    pass
            return pids
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    
    # Fallback to netstat
    try:
        result = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
        )
        if result.returncode == 0:
            import re
            pids = []
            for line in result.stdout.split("\n"):
                match = re.match(
                    r'\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)\s*$',
                    line, re.IGNORECASE
                )
                if match:
                    parsed_port = int(match.group(2))
                    pid = int(match.group(3))
                    if parsed_port == port and pid > 0:
                        pids.append(pid)
            return list(set(pids))
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    
    return []


def get_windows_process_args(pid: int) -> Optional[List[str]]:
    """
    Get command line arguments for a Windows process.
    
    Uses PowerShell or WMIC as fallback.
    
    Args:
        pid: Process ID
    
    Returns:
        List of command line arguments, or None if unavailable
    """
    if not _IS_WINDOWS:
        return None
    
    # Try PowerShell
    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                f'(Get-CimInstance Win32_Process -Filter "ProcessId = {pid}" | Select-Object -ExpandProperty CommandLine)'
            ],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
        )
        if result.returncode == 0 and result.stdout.strip():
            import shlex
            return shlex.split(result.stdout.strip())
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    
    # Fallback to WMIC
    try:
        result = subprocess.run(
            ["wmic", "process", "where", f"ProcessId={pid}", "get", "CommandLine", "/value"],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line.lower().startswith("commandline="):
                    cmd = line[len("commandline="):].strip()
                    if cmd:
                        import shlex
                        return shlex.split(cmd)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    
    return None


# ---------------------------------------------------------------------------
# Shell Detection
# ---------------------------------------------------------------------------

def detect_shell() -> str:
    """
    Detect the best available shell.
    
    On Windows: PowerShell Core > PowerShell 5.1 > cmd.exe
    On Unix: $SHELL env var > bash > sh
    
    Returns:
        Path to the shell executable
    """
    if _IS_WINDOWS:
        return _detect_windows_shell()
    else:
        return _detect_unix_shell()


def _detect_windows_shell() -> str:
    """Detect the best Windows shell."""
    # Prefer PowerShell Core (pwsh)
    pwsh = shutil.which("pwsh")
    if pwsh:
        return pwsh
    
    # Then Windows PowerShell
    powershell = shutil.which("powershell")
    if powershell:
        return powershell
    
    # Check common locations
    for candidate in [
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe"),
    ]:
        if os.path.isfile(candidate):
            return candidate
    
    # Fallback to cmd.exe
    return "cmd.exe"


def _detect_unix_shell() -> str:
    """Detect the best Unix shell."""
    # Check $SHELL
    shell = os.environ.get("SHELL")
    if shell and os.path.isfile(shell):
        return shell
    
    # Check common shells
    for name in ["bash", "zsh", "sh"]:
        path = shutil.which(name)
        if path:
            return path
    
    # Fallback paths
    for path in ["/bin/bash", "/bin/zsh", "/bin/sh"]:
        if os.path.isfile(path):
            return path
    
    return "/bin/sh"


def has_git_bash() -> bool:
    """
    Check if Git Bash is available on this system.

    On Windows: Checks HERMES_GIT_BASH_PATH env var, PATH, and common
    installation directories for bash.exe.
    On Unix: Always returns True (bash/sh is always available).

    Returns:
        True if a bash shell is available for executing commands.
    """
    if not _IS_WINDOWS:
        return True

    # Check env override first
    custom = os.environ.get("HERMES_GIT_BASH_PATH")
    if custom and os.path.isfile(custom):
        return True

    # Check PATH
    if shutil.which("bash"):
        return True

    # Check common Git Bash install locations
    for candidate in (
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Git", "bin", "bash.exe"),
        os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Git", "bin", "bash.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Git", "bin", "bash.exe"),
    ):
        if candidate and os.path.isfile(candidate):
            return True

    return False


def shell_quote(arg: str) -> str:
    """
    Quote a shell argument for the platform-appropriate shell.

    On Unix or Windows with Git Bash: uses shlex.quote (single-quote style,
    bash-compatible).
    On Windows without Git Bash: uses subprocess.list2cmdline (double-quote
    style, cmd.exe/PowerShell-compatible).

    Args:
        arg: The argument string to quote.

    Returns:
        The quoted string safe for embedding in a shell command.
    """
    if _IS_WINDOWS and not has_git_bash():
        return subprocess.list2cmdline([arg])
    import shlex
    return shlex.quote(arg)


def get_shell_args(shell: str, command: str) -> List[str]:
    """
    Get the arguments to execute a command in a shell.
    
    Args:
        shell: Path to the shell executable
        command: Command to execute
    
    Returns:
        List of arguments for subprocess
    
    On Windows:
        - bash (Git Bash): ["-lic", command]  (login interactive, sources rc files)
        - PowerShell/pwsh: ["-NoProfile", "-Command", command]
        - cmd.exe:         ["/d", "/c", command]
    
    On Unix:
        - bash/zsh/sh: ["-c", command]
    """
    shell_name = os.path.basename(shell).lower()
    
    if _IS_WINDOWS:
        if "bash" in shell_name or "sh" in shell_name:
            # Git Bash or other Unix-like shells on Windows: use -lic
            # (login + interactive + command) to source rc files
            return ["-lic", command]
        elif "powershell" in shell_name or "pwsh" in shell_name:
            return ["-NoProfile", "-Command", command]
        else:
            # cmd.exe — enable delayed expansion (/v:on) so !var!
            # syntax works for exit-code capture in wrapped commands.
            return ["/v:on", "/d", "/c", command]
    else:
        return ["-c", command]
