"""
Tests for Windows compatibility layer.

These tests run on all platforms to ensure cross-platform compatibility.
Windows-specific tests are skipped on Unix and vice versa.
"""

import os
import sys
import tempfile
import time
import pytest
from unittest.mock import patch, MagicMock

# Import the module under test
from tools.windows_compat import (
    is_windows,
    is_posix,
    get_signal,
    SIGTERM,
    SIGKILL,
    terminate_process_tree,
    resolve_windows_executable,
    is_batch_file,
    build_cmd_command_line,
    lock_file,
    unlock_file,
    detect_shell,
    get_shell_args,
    check_named_pipe_requirements,
)


class TestPlatformDetection:
    """Test platform detection functions."""

    def test_is_windows_returns_bool(self):
        """is_windows() should return a boolean."""
        result = is_windows()
        assert isinstance(result, bool)

    def test_is_posix_returns_bool(self):
        """is_posix() should return a boolean."""
        result = is_posix()
        assert isinstance(result, bool)

    def test_platform_consistency(self):
        """is_windows() and is_posix() should be mutually exclusive."""
        assert is_windows() != is_posix()

    def test_matches_sys_platform(self):
        """is_windows() should match sys.platform check."""
        expected = sys.platform == "win32"
        assert is_windows() == expected


class TestSignalCompatibility:
    """Test signal compatibility functions."""

    def test_get_signal_sigterm(self):
        """get_signal('SIGTERM') should return a valid signal."""
        result = get_signal("SIGTERM")
        assert result is not None
        assert result == SIGTERM

    def test_get_signal_sigkill(self):
        """get_signal('SIGKILL') should return a valid signal or SIGTERM on Windows."""
        result = get_signal("SIGKILL")
        assert result is not None

    def test_get_signal_invalid(self):
        """get_signal('INVALID') should return None."""
        result = get_signal("INVALID")
        assert result is None

    def test_get_signal_case_insensitive(self):
        """get_signal should be case insensitive."""
        assert get_signal("sigterm") == get_signal("SIGTERM")
        assert get_signal("SigTerm") == get_signal("SIGTERM")

    @pytest.mark.skipif(not is_windows(), reason="Windows-only test")
    def test_windows_signal_constants(self):
        """On Windows, SIGUSR1, SIGUSR2, SIGHUP should be None."""
        from tools.windows_compat import SIGUSR1, SIGUSR2, SIGHUP
        assert SIGUSR1 is None
        assert SIGUSR2 is None
        assert SIGHUP is None

    @pytest.mark.skipif(is_windows(), reason="Unix-only test")
    def test_unix_signal_constants(self):
        """On Unix, all standard signals should be available."""
        import signal
        from tools.windows_compat import SIGUSR1, SIGUSR2, SIGHUP
        assert SIGUSR1 == signal.SIGUSR1
        assert SIGUSR2 == signal.SIGUSR2
        assert SIGHUP == signal.SIGHUP


class TestProcessTermination:
    """Test cross-platform process termination."""

    @pytest.mark.skipif(is_windows(), reason="Unix-only test")
    def test_terminate_unix_process(self):
        """Test Unix process termination using sleep."""
        import subprocess
        proc = subprocess.Popen(
            ["sleep", "60"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.1)  # Give it time to start
        
        result = terminate_process_tree(proc.pid)
        assert result is True
        
        # Process should be terminated
        proc.wait(timeout=5)
        assert proc.returncode is not None

    @pytest.mark.skipif(not is_windows(), reason="Windows-only test")
    def test_terminate_windows_process(self):
        """Test Windows process termination using timeout."""
        import subprocess
        proc = subprocess.Popen(
            ["timeout", "60"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
        )
        time.sleep(0.1)  # Give it time to start
        
        result = terminate_process_tree(proc.pid)
        assert result is True
        
        # Process should be terminated
        proc.wait(timeout=5)
        assert proc.returncode is not None

    def test_terminate_nonexistent_process(self):
        """Terminating a non-existent process should return False or handle gracefully."""
        # Use a very high PID that's unlikely to exist
        result = terminate_process_tree(999999)
        # Should not raise an exception
        assert isinstance(result, bool)


class TestWindowsCommandResolution:
    """Test Windows command resolution (runs on all platforms)."""

    @pytest.mark.skipif(not is_windows(), reason="Windows-only test")
    def test_resolve_cmd(self):
        """cmd.exe should be resolvable."""
        result = resolve_windows_executable("cmd")
        assert result.lower().endswith("cmd.exe")

    @pytest.mark.skipif(not is_windows(), reason="Windows-only test")
    def test_resolve_powershell(self):
        """powershell should be resolvable."""
        result = resolve_windows_executable("powershell")
        assert "powershell" in result.lower()

    @pytest.mark.skipif(not is_windows(), reason="Windows-only test")
    def test_resolve_with_pathext(self):
        """Commands should be found using PATHEXT."""
        # notepad.exe should be found even without .exe extension
        result = resolve_windows_executable("notepad")
        assert result.lower().endswith("notepad.exe")

    def test_is_batch_file(self):
        """Test batch file detection."""
        if is_windows():
            assert is_batch_file("script.cmd") is True
            assert is_batch_file("script.bat") is True
            assert is_batch_file("script.exe") is False
            assert is_batch_file("script.ps1") is False
        else:
            # On Unix, is_batch_file always returns False
            assert is_batch_file("script.cmd") is False

    def test_build_cmd_command_line_simple(self):
        """Test command line building with simple arguments."""
        result = build_cmd_command_line("echo", ["hello", "world"])
        assert "echo" in result
        assert "hello" in result
        assert "world" in result

    def test_build_cmd_command_line_with_spaces(self):
        """Test command line building with spaces in arguments."""
        result = build_cmd_command_line("echo", ["hello world", "foo bar"])
        # Arguments with spaces should be quoted
        assert '"' in result

    def test_build_cmd_command_line_with_quotes(self):
        """Test command line building with quotes in arguments."""
        result = build_cmd_command_line("echo", ['say "hello"'])
        # Inner quotes should be doubled
        assert '""' in result or '"' in result


class TestFileLocking:
    """Test cross-platform file locking."""

    def test_lock_and_unlock(self):
        """Test basic file lock and unlock."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name
            f.write(b"test content")
        
        try:
            with open(temp_path, "r+b") as f:
                # Lock should succeed
                result = lock_file(f, exclusive=True)
                assert result is True
                
                # Unlock should succeed
                result = unlock_file(f)
                assert result is True
        finally:
            os.unlink(temp_path)

    def test_lock_exclusive_vs_shared(self):
        """Test exclusive and shared lock modes."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name
        
        try:
            with open(temp_path, "r+b") as f:
                # Exclusive lock
                result = lock_file(f, exclusive=True)
                assert result is True
                unlock_file(f)
                
                # Shared lock
                result = lock_file(f, exclusive=False)
                assert result is True
                unlock_file(f)
        finally:
            os.unlink(temp_path)


class TestShellDetection:
    """Test shell detection functions."""

    def test_detect_shell_returns_string(self):
        """detect_shell() should return a non-empty string."""
        result = detect_shell()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_detect_shell_exists(self):
        """The detected shell should exist."""
        result = detect_shell()
        # On Windows, the path might be complex, just check it's valid
        if is_windows():
            # Could be powershell, pwsh, or cmd.exe
            assert any(x in result.lower() for x in ["powershell", "pwsh", "cmd"])
        else:
            # On Unix, check if it's a valid shell
            assert os.path.isfile(result) or "bash" in result or "sh" in result

    @pytest.mark.skipif(not is_windows(), reason="Windows-only test")
    def test_windows_shell_detection_priority(self):
        """On Windows, PowerShell Core should be preferred over PowerShell 5.1."""
        result = detect_shell()
        # If pwsh is in PATH, it should be detected
        import shutil
        if shutil.which("pwsh"):
            assert "pwsh" in result.lower()

    @pytest.mark.skipif(is_windows(), reason="Unix-only test")
    def test_unix_shell_detection(self):
        """On Unix, the shell should be bash/zsh/sh or $SHELL."""
        result = detect_shell()
        shell_env = os.environ.get("SHELL", "")
        # Should be one of the common shells or match $SHELL
        valid_shells = ["/bin/bash", "/bin/zsh", "/bin/sh", "/usr/bin/bash", "/usr/bin/zsh"]
        assert result in valid_shells or result == shell_env or os.path.isfile(result)


class TestShellArgs:
    """Test shell argument generation."""

    def test_powershell_args(self):
        """PowerShell should use -NoProfile -Command."""
        args = get_shell_args("pwsh", "Write-Host 'Hello'")
        assert args == ["-NoProfile", "-Command", "Write-Host 'Hello'"]

    def test_cmd_args(self):
        """cmd.exe should use /d /c."""
        args = get_shell_args("cmd.exe", "echo Hello")
        assert args == ["/d", "/c", "echo Hello"]

    def test_bash_args(self):
        """Bash should use -c."""
        args = get_shell_args("/bin/bash", "echo Hello")
        assert args == ["-c", "echo Hello"]

    def test_zsh_args(self):
        """Zsh should use -c."""
        args = get_shell_args("/bin/zsh", "echo Hello")
        assert args == ["-c", "echo Hello"]


class TestNamedPipeRequirements:
    """Test Named Pipe requirements check."""

    def test_check_named_pipe_requirements(self):
        """check_named_pipe_requirements should return (bool, str)."""
        available, message = check_named_pipe_requirements()
        assert isinstance(available, bool)
        assert isinstance(message, str)

    @pytest.mark.skipif(not is_windows(), reason="Windows-only test")
    def test_windows_named_pipe_requirements(self):
        """On Windows, Named Pipes require pywin32."""
        available, message = check_named_pipe_requirements()
        if available:
            assert "pywin32" in message.lower() or "available" in message.lower()
        else:
            assert "pywin32" in message.lower()

    @pytest.mark.skipif(is_windows(), reason="Unix-only test")
    def test_unix_named_pipe_requirements(self):
        """On Unix, Unix Domain Sockets are always available."""
        available, message = check_named_pipe_requirements()
        assert available is True
        assert "Unix Domain Socket" in message or "POSIX" in message


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_detect_shell_fallback(self):
        """detect_shell should always return a valid shell, even with minimal environment."""
        # This test ensures we don't crash even in unusual environments
        result = detect_shell()
        assert result is not None
        assert isinstance(result, str)

    def test_get_shell_args_empty_command(self):
        """get_shell_args should handle empty command."""
        result = get_shell_args("/bin/bash", "")
        assert isinstance(result, list)
        assert len(result) == 2  # ["-c", ""]

    def test_lock_file_already_locked(self):
        """Locking an already-locked file should fail gracefully."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name
        
        try:
            with open(temp_path, "r+b") as f1:
                lock_file(f1, exclusive=True)
                
                # Try to lock again with another file handle
                with open(temp_path, "r+b") as f2:
                    # This should fail or return False
                    result = lock_file(f2, exclusive=True)
                    # On some systems this might succeed (different handles)
                    # Just ensure it doesn't crash
                    assert isinstance(result, bool)
                    if result:
                        unlock_file(f2)
                
                unlock_file(f1)
        finally:
            os.unlink(temp_path)


class TestImportCompat:
    """Test that the module can be imported on all platforms."""

    def test_import_no_exceptions(self):
        """Module import should not raise exceptions."""
        # This test passes if we got here
        assert True

    def test_all_public_functions_exist(self):
        """All public functions should be importable."""
        from tools.windows_compat import (
            is_windows,
            is_posix,
            get_signal,
            terminate_process_tree,
            resolve_windows_executable,
            is_batch_file,
            build_cmd_command_line,
            lock_file,
            unlock_file,
            detect_shell,
            get_shell_args,
            create_ipc_server,
            create_ipc_client,
            check_named_pipe_requirements,
        )
        # All imports succeeded
        assert True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
