import os
import sys
import subprocess
import platform
import json
import time
import threading
import queue
import glob
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class ExternalToolExecutor:
    """
    Executes external security tools in separate terminals and manages their lifecycle.
    Supports cross-platform terminal execution and automatic cleanup.
    """
    
    def __init__(self, project_root: str = None, wordlists_dir: str = 'lists'):
        self.project_root = project_root or os.getcwd()
        # Ensure lists_dir is always an absolute path
        if os.path.isabs(wordlists_dir):
            self.lists_dir = wordlists_dir
        else:
            self.lists_dir = os.path.abspath(os.path.join(self.project_root, wordlists_dir))
        self.tools_config_path = os.path.join(self.project_root, "tools_config.json")
        self.active_processes = {}
        self.tool_results = {}
        
    def get_platform_terminal_command(self, tool_name: str, command: str, working_dir: str = None) -> Tuple[str, List[str]]:
        """
        Get platform-specific terminal command and arguments.
        
        Parameters:
            tool_name: Name of the tool being executed
            command: The command to execute
            working_dir: Working directory for the command
            
        Returns:
            Tuple of (terminal_command, arguments_list)
        """
        system = platform.system().lower()
        
        if system == "darwin":  # macOS
            # Use Terminal.app with AppleScript
            # Don't change directory since command already has absolute paths
            script = f'''
tell application "Terminal"
    do script "{command} && echo '\\n[TOOL_EXECUTION_COMPLETE]' && exit"
    activate
end tell
'''
            return "osascript", ["-e", script]
            
        elif system == "windows":
            # Use cmd.exe with /k to keep window open until command completes
            # Don't change directory since command already has absolute paths
            full_command = f'{command} && echo [TOOL_EXECUTION_COMPLETE] && exit'
            return "cmd.exe", ["/k", full_command]
            
        else:  # Linux and other Unix-like systems
            # Use xterm or gnome-terminal if available
            # Don't change directory since command already has absolute paths
            full_command = f'{command} && echo "[TOOL_EXECUTION_COMPLETE]" && exit'
            
            # Try different terminal emulators
            terminals = ["gnome-terminal", "xterm", "konsole", "terminator"]
            for terminal in terminals:
                try:
                    subprocess.run([terminal, "--version"], capture_output=True, check=True)
                    if terminal == "gnome-terminal":
                        return terminal, ["--", "bash", "-c", full_command]
                    elif terminal == "xterm":
                        return terminal, ["-e", f"bash -c '{full_command}'"]
                    elif terminal == "konsole":
                        return terminal, ["-e", f"bash -c '{full_command}'"]
                    elif terminal == "terminator":
                        return terminal, ["-e", f"bash -c '{full_command}'"]
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
            
            # Fallback to subprocess with shell
            return "bash", ["-c", full_command]
    
    def resolve_paths_in_command(self, command: str, parameters: Dict[str, str]) -> str:
        """
        Resolve relative paths in command to absolute paths.
        
        Parameters:
            command: The command template
            parameters: Parameters to substitute
            
        Returns:
            Command with resolved paths
        """
        resolved_command = command
        
        # First handle parameter substitutions
        for param_name, param_value in parameters.items():
            # Regular parameter substitution
            resolved_command = resolved_command.replace(f"{{{param_name}}}", str(param_value))
        
        # Then resolve wordlist parameters in the format {wordlist:filename}
        import re
        wordlist_pattern = r'\{wordlist:([^}]+)\}'
        wordlist_matches = re.findall(wordlist_pattern, resolved_command)
        
        if wordlist_matches:
            logger.debug(f"[ExternalToolExecutor] Found wordlist parameters: {wordlist_matches}")
            for filename in wordlist_matches:
                # Construct full path to wordlist file
                wordlist_path = os.path.join(self.lists_dir, filename)
                if platform.system().lower() == "windows":
                    wordlist_path = wordlist_path.replace('/', '\\')
                
                # Replace the wordlist parameter with full path
                placeholder = f"{{wordlist:{filename}}}"
                resolved_command = resolved_command.replace(placeholder, wordlist_path)
                
                logger.debug(f"[ExternalToolExecutor] Replaced {placeholder} with {wordlist_path}")
        
        # Legacy support: Also resolve any lists/ paths in the final command (for backward compatibility)
        # This ensures backward compatibility with old tools_config.json files
        # Only process if we haven't already handled wordlist parameters to avoid duplication
        if "lists/" in resolved_command and not wordlist_matches:
            # Use the already absolute lists_dir path
            lists_abs_path = self.lists_dir
            if platform.system().lower() == "windows":
                lists_abs_path = lists_abs_path.replace('/', '\\')
            
            logger.debug(f"[ExternalToolExecutor] Replacing legacy 'lists/' with '{lists_abs_path}/'")
            logger.debug(f"[ExternalToolExecutor] Before replacement: {resolved_command}")
            
            # Use regex to replace all occurrences of lists/ with absolute path
            resolved_command = re.sub(r'lists/', f"{lists_abs_path}/", resolved_command)
            
            logger.debug(f"[ExternalToolExecutor] After regex replacement: {resolved_command}")
            
            # Verify replacement was successful by checking if original relative paths still exist
            # Note: We check for the original 'lists/' pattern, not the absolute path that contains 'lists'
            original_lists_pattern = r'(?<![/\\])lists/'
            if re.search(original_lists_pattern, resolved_command):
                logger.warning(f"[ExternalToolExecutor] Original 'lists/' paths still found after replacement")
            else:
                logger.debug(f"[ExternalToolExecutor] All 'lists/' paths successfully replaced with absolute paths")
        
        return resolved_command
    
    def _escape_command_for_shell(self, command: str) -> str:
        """
        Properly escape command for shell execution, handling URLs and special characters.
        
        Parameters:
            command: The command to escape
            
        Returns:
            Escaped command safe for shell execution
        """
        # For complex commands with special characters, use a more sophisticated approach
        # First, try to identify if this is a simple command or complex one
        
        # Check if command contains complex structures like parentheses, commas, or multiple quotes
        has_complex_structure = any(char in command for char in ['(', ')', ',', ';', '|', '>', '<'])
        has_multiple_quotes = command.count("'") > 2 or command.count('"') > 2
        
        if has_complex_structure or has_multiple_quotes:
            # For complex commands, use a different strategy
            return self._escape_complex_command(command)
        else:
            # For simple commands, use the standard argument-by-argument approach
            return self._escape_simple_command(command)
    
    def _escape_simple_command(self, command: str) -> str:
        """Escape simple commands by handling arguments individually."""
        parts = command.split()
        if not parts:
            return command
        
        tool_name = parts[0]
        args = parts[1:]
        
        escaped_args = []
        for arg in args:
            # Check if argument contains special characters that need escaping
            needs_escaping = any(char in arg for char in [
                'http://', 'https://', '&', '%', '?', '=', 
                ' ', '"', "'", '\\', '$', '`', '!', '*', '[', ']'
            ])
            
            if needs_escaping:
                # Escape any existing single quotes and wrap in single quotes
                escaped_arg = arg.replace("'", "'\"'\"'")
                escaped_args.append(f"'{escaped_arg}'")
            else:
                escaped_args.append(arg)
        
        escaped_command = f"{tool_name} {' '.join(escaped_args)}"
        logger.debug(f"[ExternalToolExecutor] Simple escaped: {escaped_command}")
        return escaped_command
    
    def _escape_complex_command(self, command: str) -> str:
        """Escape complex commands with special structures."""
        # For complex commands, we need to be more careful
        # Handle special cases like parentheses and commas that might be part of arguments
        
        # Special case: if the command contains parentheses with commas, it's likely a tuple/list argument
        if '(' in command and ')' in command and ',' in command:
            return self._escape_tuple_argument_command(command)
        
        import shlex
        try:
            # Use shlex to properly parse the command
            parsed = shlex.split(command)
            logger.debug(f"[ExternalToolExecutor] Parsed complex command: {parsed}")
            
            # Reconstruct with proper escaping
            escaped_parts = []
            for part in parsed:
                if any(char in part for char in ['(', ')', ',', ';', '|', '>', '<', '&', '%', '?', '=', ' ']):
                    # Escape special characters and wrap in single quotes
                    escaped_part = part.replace("'", "'\"'\"'")
                    escaped_parts.append(f"'{escaped_part}'")
                else:
                    escaped_parts.append(part)
            
            escaped_command = ' '.join(escaped_parts)
            logger.debug(f"[ExternalToolExecutor] Complex escaped: {escaped_command}")
            return escaped_command
            
        except Exception as e:
            logger.warning(f"[ExternalToolExecutor] Failed to parse complex command with shlex: {str(e)}")
            # Fallback: wrap the entire command in single quotes
            escaped_command = command.replace("'", "'\"'\"'")
            escaped_command = f"'{escaped_command}'"
            logger.debug(f"[ExternalToolExecutor] Fallback escaped: {escaped_command}")
            return escaped_command
    
    def _escape_tuple_argument_command(self, command: str) -> str:
        """Handle commands with tuple/list arguments like ('etail', 'php')."""
        # This is a special case for commands that have tuple arguments
        # We need to preserve the tuple structure while escaping properly
        
        # Find the tuple argument
        import re
        
        # Pattern to match tuple-like arguments: ('value1', 'value2') or (value1, value2)
        tuple_pattern = r'\([^)]*\)'
        
        def escape_tuple(match):
            tuple_content = match.group(0)
            # Escape the tuple content and wrap in single quotes
            escaped_tuple = tuple_content.replace("'", "'\"'\"'")
            return f"'{escaped_tuple}'"
        
        # Replace tuple arguments with escaped versions
        escaped_command = re.sub(tuple_pattern, escape_tuple, command)
        
        # Also escape any remaining special characters in other parts
        parts = escaped_command.split()
        escaped_parts = []
        
        for part in parts:
            if part.startswith("'(") and part.endswith(")'"):
                # This is our escaped tuple, keep it as is
                escaped_parts.append(part)
            elif any(char in part for char in ['http://', 'https://', '&', '%', '?', '=', ' ']):
                # Escape other special characters
                escaped_part = part.replace("'", "'\"'\"'")
                escaped_parts.append(f"'{escaped_part}'")
            else:
                escaped_parts.append(part)
        
        final_command = ' '.join(escaped_parts)
        logger.debug(f"[ExternalToolExecutor] Tuple escaped: {final_command}")
        return final_command
    
    def execute_tool_in_terminal(self, tool_name: str, parameters: Dict[str, str], 
                                timeout: int = 300) -> Dict[str, str]:
        """
        Execute a tool in a separate terminal and wait for completion.
        
        Parameters:
            tool_name: Name of the tool to execute
            parameters: Parameters for the tool
            timeout: Maximum execution time in seconds
            
        Returns:
            Dictionary containing execution results
        """
        try:
            # Load tool configuration
            with open(self.tools_config_path, 'r') as f:
                tools_config = json.load(f)
            
            tool_config = next((tool for tool in tools_config if tool["tool_name"] == tool_name), None)
            if not tool_config:
                return {
                    "success": False,
                    "error": f"Tool {tool_name} not found in configuration",
                    "output": "",
                    "execution_time": 0
                }
            
            # Build the command
            command_template = tool_config["command"]
            resolved_command = self.resolve_paths_in_command(command_template, parameters)
            
            logger.info(f"[ExternalToolExecutor] Executing {tool_name} with command: {resolved_command}")
            
            # Execute the command in a new terminal window
            start_time = time.time()
            
            if platform.system().lower() == "darwin":
                # macOS: Use AppleScript to open Terminal.app with the command
                # Properly escape the command for shell execution
                escaped_command = self._escape_command_for_shell(resolved_command)
                # Don't change directory since resolved_command already has absolute paths
                applescript = f'''
                tell application "Terminal"
                    activate
                    do script "{escaped_command} && echo '[TOOL_EXECUTION_COMPLETE]' && sleep 1 && exit 0"
                end tell
                '''
                
                # Execute AppleScript to open terminal
                subprocess.run(["osascript", "-e", applescript], check=True)
                
                # Wait for tool completion (this is a simplified approach)
                # In a real implementation, you'd want to monitor the terminal output
                time.sleep(5)  # Give some time for the tool to start
                
                execution_time = time.time() - start_time
                return {
                    "success": True,
                    "output": f"Tool {tool_name} started in new Terminal.app window. Command: {resolved_command}",
                    "execution_time": execution_time,
                    "command": resolved_command,
                    "note": "Tool is running in separate terminal window. Check the terminal for output."
                }
                
            elif platform.system().lower() == "windows":
                # Windows: Use cmd.exe to open new command prompt
                escaped_command = self._escape_command_for_shell(resolved_command)
                # Don't change directory since resolved_command already has absolute paths
                cmd_command = f'start "Security Tool - {tool_name}" cmd /k "{escaped_command} && echo [TOOL_EXECUTION_COMPLETE] && timeout /t 1 /nobreak >nul && exit"'
                
                subprocess.run(cmd_command, shell=True, check=True)
                
                # Wait for tool completion
                time.sleep(5)
                
                execution_time = time.time() - start_time
                return {
                    "success": True,
                    "output": f"Tool {tool_name} started in new Command Prompt window. Command: {resolved_command}",
                    "execution_time": execution_time,
                    "command": resolved_command,
                    "note": "Tool is running in separate command prompt window. Check the window for output."
                }
                
            else:
                # Linux: Try different terminal emulators
                escaped_command = self._escape_command_for_shell(resolved_command)
                # Don't change directory since resolved_command already has absolute paths
                terminal_commands = [
                    ("gnome-terminal", f"-- bash -c '{escaped_command} && echo [TOOL_EXECUTION_COMPLETE] && sleep 1 && exit 0'"),
                    ("xterm", f"-e 'bash -c \"{escaped_command} && echo [TOOL_EXECUTION_COMPLETE] && sleep 1 && exit 0\"'"),
                    ("konsole", f"-e 'bash -c \"{escaped_command} && echo [TOOL_EXECUTION_COMPLETE] && sleep 1 && exit 0\"'")
                ]
                
                for term_cmd, term_args in terminal_commands:
                    try:
                        subprocess.run([term_cmd] + term_args.split(), check=True)
                        time.sleep(5)
                        break
                    except (subprocess.CalledProcessError, FileNotFoundError):
                        continue
                else:
                    # Fallback to subprocess if no terminal emulator found
                    result = subprocess.run(
                        resolved_command.split(),
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        cwd=self.project_root
                    )
                    execution_time = time.time() - start_time
                    
                    return {
                        "success": True,
                        "output": result.stdout,
                        "error": result.stderr if result.stderr else "",
                        "execution_time": execution_time,
                        "command": resolved_command,
                        "return_code": result.returncode
                    }
                
                execution_time = time.time() - start_time
                return {
                    "success": True,
                    "output": f"Tool {tool_name} started in new terminal window. Command: {resolved_command}",
                    "execution_time": execution_time,
                    "command": resolved_command,
                    "note": "Tool is running in separate terminal window. Check the window for output."
                }
                    
        except Exception as e:
            logger.error(f"[ExternalToolExecutor] Error executing tool {tool_name}: {str(e)}")
            return {
                "success": False,
                "error": f"Execution error: {str(e)}",
                "output": "",
                "execution_time": 0,
                "command": command_template if 'command_template' in locals() else ""
            }
    
    def execute_tool_with_wait(self, tool_name: str, parameters: Dict[str, str], 
                              timeout: int = 300) -> Dict[str, str]:
        """
        Execute a tool and automatically wait for completion, then return results.
        
        Parameters:
            tool_name: Name of the tool to execute
            parameters: Parameters for the tool
            timeout: Maximum execution time in seconds
            
        Returns:
            Dictionary containing execution results
        """
        logger.info(f"[ExternalToolExecutor] Starting execution of {tool_name}")
        
        # Execute the tool in new terminal window
        result = self.execute_tool_in_terminal(tool_name, parameters, timeout)
        
        if result["success"]:
            logger.info(f"[ExternalToolExecutor] {tool_name} started in new terminal window")
            
            # Show tool execution status
            print(f"\n{'='*80}")
            print(f"🔧 EXTERNAL TOOL EXECUTION: {tool_name.upper()}")
            print(f"{'='*80}")
            print(f"📋 Command: {result['command']}")
            print(f"🖥️  Tool is now running in a new terminal window")
            print(f"⏳ Auto-waiting for tool completion (no user input required)...")
            print(f"📝 Check the terminal window for real-time output")
            print(f"{'='*80}")
            
            # Automatically wait for tool completion and read results - NO USER INPUT REQUIRED
            try:
                # Smart waiting strategy - check for completion based on tool type and complexity
                import time
                
                # Get tool-specific wait parameters
                tool_wait_params = self._get_tool_wait_parameters(tool_name)
                max_wait_time = min(timeout, tool_wait_params["max_wait"])
                check_interval = tool_wait_params["check_interval"]
                min_wait_time = tool_wait_params["min_wait"]
                
                print(f"⏳ Smart-waiting for {tool_name} to complete...")
                print(f"📊 Wait parameters: min={min_wait_time}s, max={max_wait_time}s, check every {check_interval}s")
                
                total_wait_time = 0
                tool_completed = False
                tool_failed = False
                
                # Wait for minimum time first (tools need time to start and produce output)
                print(f"⏳ Waiting minimum {min_wait_time}s for {tool_name} to start...")
                time.sleep(min_wait_time)
                total_wait_time = min_wait_time
                
                # Then check periodically for completion
                while total_wait_time < max_wait_time and not tool_completed and not tool_failed:
                    time.sleep(check_interval)
                    total_wait_time += check_interval
                    
                    # Check if tool has completed (multiple detection methods)
                    completion_status = self._check_tool_completion(tool_name, result.get("command", ""))
                    
                    if completion_status["completed"]:
                        # Tool completed successfully
                        tool_completed = True
                        result["output"] = f"Tool {tool_name} execution results:\n{completion_status['results']}"
                        result["detailed_results"] = completion_status['results']
                        result["user_confirmed"] = True
                        result["has_results"] = True
                        result["auto_captured"] = True
                        result["actual_wait_time"] = total_wait_time
                        result["completion_method"] = completion_status['method']
                        
                        print(f"✅ Tool {tool_name} completed in {total_wait_time}s - RESULTS CAPTURED")
                        print(f"📊 Completion method: {completion_status['method']}")
                        print(f"📊 Auto-captured {tool_name} results: {len(completion_status['results'])} characters")
                        
                        # Wait a bit more to ensure tool has finished writing output
                        print(f"⏳ Waiting additional 5s for output stabilization...")
                        time.sleep(5)
                        
                        # Now close the terminal after successful completion
                        print(f"🔒 Closing terminal for {tool_name}...")
                        self._close_tool_terminals(tool_name, "completed_successfully")
                        
                        break
                    
                    elif completion_status["failed"]:
                        # Tool execution failed
                        tool_failed = True
                        result["output"] = f"Tool {tool_name} execution failed: {completion_status['failure_reason']}"
                        result["has_results"] = False
                        result["auto_captured"] = False
                        result["user_confirmed"] = True
                        result["tool_execution_failed"] = True
                        result["failure_reason"] = completion_status['failure_reason']
                        
                        print(f"❌ Tool {tool_name} execution failed: {completion_status['failure_reason']}")
                        print(f"💡 AI will continue with alternative strategies")
                        
                        # Close terminal for failed tool
                        self._close_tool_terminals(tool_name, "failed")
                        break
                    
                    # Show progress
                    if total_wait_time % 30 == 0:  # Show progress every 30 seconds
                        remaining = max_wait_time - total_wait_time
                        print(f"⏳ Still waiting for {tool_name}... ({remaining}s remaining)")
                        print(f"🔍 Last check: {completion_status['status']}")
                
                # If we reached max wait time without completion
                if total_wait_time >= max_wait_time and not tool_completed and not tool_failed:
                    print(f"⏰ Tool {tool_name} exceeded maximum wait time ({max_wait_time}s)")
                    print(f"💡 Tool may still be running - letting AI decide next steps")
                    
                    # Try one final completion check
                    final_status = self._check_tool_completion(tool_name, result.get("command", ""))
                    
                    if final_status["completed"]:
                        result["output"] = f"Tool {tool_name} results (captured at timeout):\n{final_status['results']}"
                        result["detailed_results"] = final_status['results']
                        result["has_results"] = True
                        result["auto_captured"] = True
                        print(f"📊 Captured results at timeout: {len(final_status['results'])} characters")
                    else:
                        result["output"] = f"Tool {tool_name} exceeded time limit - tool may still be running"
                        result["has_results"] = False
                        result["auto_captured"] = False
                        print(f"⚠️  Tool {tool_name} may still be running - check terminal manually")
                    
                    result["user_confirmed"] = True
                    result["timeout_reached"] = True
                    result["tool_may_be_running"] = True
                
            except Exception as e:
                logger.warning(f"[ExternalToolExecutor] Error during automatic result capture: {str(e)}")
                result["output"] = f"Tool {tool_name} execution completed automatically but result capture failed: {str(e)}"
                result["user_confirmed"] = False
                result["auto_captured"] = False
                
        else:
            logger.error(f"[ExternalToolExecutor] {tool_name} failed: {result['error']}")
            print(f"❌ Tool {tool_name} failed to start: {result['error']}")
            print(f"💡 AI will continue with internal tools and manual testing strategies")
            
            # Always try to close terminal windows for failed tools (cross-platform)
            self._close_tool_terminals(tool_name, "failed")
            
            # Update result to indicate failure but allow AI to continue
            result["ai_should_continue"] = True
            result["fallback_strategy"] = "Continue with internal tools, manual testing, and alternative attack vectors"
            result["tool_failed"] = True
            result["failure_reason"] = result.get("error", "Unknown error")
        
        # Always try to close terminal windows after tool execution (success or failure)
        self._close_tool_terminals(tool_name, "completed")
        
        return result
    
    def _close_tool_terminals(self, tool_name: str, reason: str):
        """
        Close terminal windows for a specific tool (cross-platform).
        
        Parameters:
            tool_name: Name of the tool whose terminals should be closed
            reason: Reason for closing (e.g., 'completed', 'failed', 'timeout')
        """
        try:
            if platform.system().lower() == "darwin":  # macOS
                # More aggressive terminal closing for macOS
                applescript = f'''
                tell application "Terminal"
                    repeat with w in windows
                        try
                            if name of w contains "{tool_name}" or name of w contains "TOOL_EXECUTION_COMPLETE" then
                                close w
                            end if
                        on error
                            -- Try to close any terminal that might be related
                            try
                                close w
                            end try
                        end try
                    end repeat
                end tell
                '''
                subprocess.run(["osascript", "-e", applescript], check=False)
                
                # Additional cleanup: try to close any remaining terminals
                cleanup_script = '''
                tell application "Terminal"
                    repeat with w in windows
                        try
                            if name of w contains "TOOL_EXECUTION_COMPLETE" then
                                close w
                            end if
                        end try
                    end repeat
                end tell
                '''
                subprocess.run(["osascript", "-e", cleanup_script], check=False)
                
                print(f"🔒 Closed terminal windows for {tool_name} ({reason})")
                
            elif platform.system().lower() == "windows":  # Windows
                # Close cmd.exe windows that contain the tool name
                try:
                    import psutil
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        try:
                            if proc.info['name'] == 'cmd.exe' and proc.info['cmdline']:
                                cmd_line = ' '.join(proc.info['cmdline'])
                                if tool_name.lower() in cmd_line.lower() or "TOOL_EXECUTION_COMPLETE" in cmd_line:
                                    proc.terminate()
                                    print(f"🔒 Terminated Windows terminal for {tool_name} ({reason})")
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                except ImportError:
                    # Fallback to taskkill if psutil not available
                    subprocess.run(["taskkill", "/f", "/im", "cmd.exe"], check=False, 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    print(f"🔒 Closed Windows terminals for {tool_name} ({reason})")
                    
            else:  # Linux
                # Close xterm, gnome-terminal, etc.
                try:
                    import psutil
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        try:
                            if proc.info['name'] in ['xterm', 'gnome-terminal', 'konsole', 'terminator']:
                                cmd_line = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                                if tool_name.lower() in cmd_line.lower() or "TOOL_EXECUTION_COMPLETE" in cmd_line:
                                    proc.terminate()
                                    print(f"🔒 Terminated Linux terminal for {tool_name} ({reason})")
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                except ImportError:
                    # Fallback to pkill if psutil not available
                    subprocess.run(["pkill", "-f", tool_name], check=False,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    print(f"🔒 Closed Linux terminals for {tool_name} ({reason})")
                    
        except Exception as e:
            logger.warning(f"[ExternalToolExecutor] Failed to close terminals for {tool_name}: {str(e)}")
    
    def _is_tool_execution_failed(self, tool_name: str) -> bool:
        """
        Check if tool execution has failed during runtime.
        
        Parameters:
            tool_name: Name of the tool to check
            
        Returns:
            True if tool execution failed, False otherwise
        """
        try:
            # Check if the tool command exists in the system
            import shutil
            tool_config = self._get_tool_config(tool_name)
            if not tool_config:
                return True
            
            command_template = tool_config["command"]
            # Extract the actual command (first word)
            command_parts = command_template.split()
            if not command_parts:
                return True
            
            actual_command = command_parts[0]
            
            # Check if command exists in PATH
            if not shutil.which(actual_command):
                logger.warning(f"[ExternalToolExecutor] Command '{actual_command}' not found in PATH")
                return True
            
            # Check if there are any error files or logs indicating failure
            error_patterns = [
                f"{tool_name}_error.log",
                f"{tool_name}_failed.log", 
                f"{tool_name}_error.txt",
                f"{tool_name}_failed.txt"
            ]
            
            for error_file in error_patterns:
                if os.path.exists(error_file):
                    logger.warning(f"[ExternalToolExecutor] Found error file: {error_file}")
                    return True
            
            # Check if terminal is still running (if not, tool might have crashed)
            if platform.system().lower() == "darwin":  # macOS
                try:
                    import subprocess
                    # Check if any terminal windows are still running for this tool
                    applescript = f'''
                    tell application "Terminal"
                        set windowCount to count of windows
                        repeat with i from 1 to windowCount
                            set windowName to name of window i
                            if windowName contains "{tool_name}" then
                                return true
                            end if
                        end repeat
                        return false
                    end tell
                    '''
                    result = subprocess.run(["osascript", "-e", applescript], 
                                         capture_output=True, text=True, check=False)
                    if result.stdout.strip() == "false":
                        logger.warning(f"[ExternalToolExecutor] No terminal windows found for {tool_name}")
                        return True
                except Exception as e:
                    logger.warning(f"[ExternalToolExecutor] Error checking terminal status: {str(e)}")
            
            return False
            
        except Exception as e:
            logger.error(f"[ExternalToolExecutor] Error checking tool execution status: {str(e)}")
            return True
    
    def _get_tool_config(self, tool_name: str) -> dict:
        """
        Get tool configuration from tools_config.json.
        
        Parameters:
            tool_name: Name of the tool
            
        Returns:
            Tool configuration dictionary or None if not found
        """
        try:
            with open(self.tools_config_path, 'r') as f:
                tools_config = json.load(f)
            
            tool_config = next((tool for tool in tools_config if tool["tool_name"] == tool_name), None)
            return tool_config
        except Exception as e:
            logger.error(f"[ExternalToolExecutor] Error loading tool config: {str(e)}")
            return None
    
    def _read_tool_results(self, tool_name: str, command: str) -> str:
        """
        Automatically read tool execution results from output files.
        
        Parameters:
            tool_name: Name of the tool that was executed
            command: The command that was executed
            
        Returns:
            Tool execution results as string
        """
        try:
            # Define output file patterns for different tools
            output_patterns = {
                "nikto": ["nikto_scan.txt", "nikto_output.txt"],
                "nmap": ["nmap_scan.txt", "nmap_output.txt"],
                "sqlmap": ["sqlmap_results", "sqlmap_output.txt"],
                "gobuster": ["gobuster_results.txt", "gobuster_output.txt"],
                "dirb": ["dirb_results.txt", "dirb_output.txt"],
                "wfuzz": ["wfuzz_results.txt", "wfuzz_output.txt"],
                "hydra": ["hydra_results.txt", "hydra_output.txt"],
                "amass": ["amass_results.txt", "amass_output.txt"],
                "whatweb": ["whatweb_results.txt", "whatweb_output.txt"],
                "theharvester": ["theharvester_results.txt", "theharvester_output.txt"]
            }
            
            # Get possible output files for this tool
            possible_files = output_patterns.get(tool_name.lower(), [])
            
            # Also check for any files that might contain the tool name
            import glob
            tool_files = glob.glob(f"*{tool_name.lower()}*")
            possible_files.extend(tool_files)
            
            # Try to read from possible output files
            for filename in possible_files:
                if os.path.exists(filename):
                    try:
                        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read().strip()
                            if content:
                                logger.info(f"[ExternalToolExecutor] Successfully read results from {filename}")
                                return content
                    except Exception as e:
                        logger.warning(f"[ExternalToolExecutor] Failed to read {filename}: {str(e)}")
                        continue
            
            # If no output files found, try to capture from command output
            # This handles tools that output to stdout/stderr
            if command:
                try:
                    # Try to execute the command again with capture to get output
                    import subprocess
                    import shlex
                    
                    # Parse command and execute with capture
                    cmd_parts = shlex.split(command)
                    if cmd_parts:
                        # Remove output redirection if present
                        clean_cmd = []
                        for part in cmd_parts:
                            if not part.startswith('-o') and not part.startswith('--output'):
                                clean_cmd.append(part)
                        
                        if clean_cmd:
                            # Execute with timeout to get output
                            process = subprocess.run(
                                clean_cmd,
                                capture_output=True,
                                text=True,
                                timeout=30,  # Short timeout for output capture
                                cwd=self.project_root
                            )
                            
                            if process.stdout or process.stderr:
                                output = f"STDOUT: {process.stdout}\nSTDERR: {process.stderr}".strip()
                                if output:
                                    logger.info(f"[ExternalToolExecutor] Captured output from command execution")
                                    return output
                except Exception as e:
                    logger.warning(f"[ExternalToolExecutor] Failed to capture command output: {str(e)}")
            
            # If still no results, return empty string
            logger.warning(f"[ExternalToolExecutor] No results could be automatically captured for {tool_name}")
            return ""
            
        except Exception as e:
            logger.error(f"[ExternalToolExecutor] Error reading tool results: {str(e)}")
            return ""
    
    def get_available_tools(self) -> List[Dict[str, str]]:
        """
        Get list of available external tools from configuration.
        
        Returns:
            List of tool configurations
        """
        try:
            with open(self.tools_config_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"[ExternalToolExecutor] Error loading tools configuration: {str(e)}")
            return []
    
    def validate_tool_parameters(self, tool_name: str, parameters: Dict[str, str]) -> Tuple[bool, str]:
        """
        Validate that the provided parameters match the tool's requirements.
        
        Parameters:
            tool_name: Name of the tool
            parameters: Parameters to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        tools = self.get_available_tools()
        tool_config = next((tool for tool in tools if tool["tool_name"] == tool_name), None)
        
        if not tool_config:
            return False, f"Tool {tool_name} not found"
        
        required_params = {param["name"] for param in tool_config.get("parameters", [])}
        provided_params = set(parameters.keys())
        
        if required_params != provided_params:
            missing = required_params - provided_params
            extra = provided_params - required_params
            error_msg = f"Parameter mismatch for {tool_name}. "
            if missing:
                error_msg += f"Missing: {missing}. "
            if extra:
                error_msg += f"Extra: {extra}. "
            error_msg += f"Required: {required_params}"
            return False, error_msg
        
        return True, ""
    
    def cleanup_resources(self):
        """Clean up any remaining resources."""
        for process_id, process_info in self.active_processes.items():
            try:
                if process_info["process"].poll() is None:
                    process_info["process"].terminate()
                    logger.info(f"[ExternalToolExecutor] Terminated process {process_id}")
            except Exception as e:
                logger.error(f"[ExternalToolExecutor] Error terminating process {process_id}: {str(e)}")
        
        self.active_processes.clear()
        self.tool_results.clear()
    
    def cleanup(self):
        """Alias for cleanup_resources for compatibility."""
        self.cleanup_resources()
    
    def _get_tool_wait_parameters(self, tool_name: str) -> Dict[str, int]:
        """
        Get tool-specific wait parameters from tools_config.json.
        
        Parameters:
            tool_name: Name of the tool
            
        Returns:
            Dictionary with wait parameters
        """
        # Default parameters for unknown tools
        default_params = {
            "max_wait": 300,      # 5 minutes
            "min_wait": 15,       # 15 seconds minimum
            "check_interval": 10  # Check every 10 seconds
        }
        
        try:
            # Load tool configuration from JSON
            with open(self.tools_config_path, 'r') as f:
                tools_config = json.load(f)
            
            # Find the specific tool configuration
            tool_config = next((tool for tool in tools_config if tool["tool_name"].lower() == tool_name.lower()), None)
            
            if tool_config and "wait_parameters" in tool_config:
                # Use the wait parameters from JSON configuration
                json_params = tool_config["wait_parameters"]
                
                # Validate and return the parameters
                return {
                    "max_wait": json_params.get("max_wait", default_params["max_wait"]),
                    "min_wait": json_params.get("min_wait", default_params["min_wait"]),
                    "check_interval": json_params.get("check_interval", default_params["check_interval"])
                }
            else:
                # Tool not found or no wait_parameters defined, use defaults
                logger.debug(f"[ExternalToolExecutor] No wait_parameters found for {tool_name}, using defaults")
                return default_params
                
        except Exception as e:
            logger.warning(f"[ExternalToolExecutor] Error loading wait parameters for {tool_name}: {str(e)}, using defaults")
            return default_params
    
    def _check_tool_completion(self, tool_name: str, command: str) -> Dict[str, any]:
        """
        Check if a tool has completed execution using multiple detection methods.
        
        Parameters:
            tool_name: Name of the tool
            command: The command that was executed
            
        Returns:
            Dictionary with completion status
        """
        try:
            # Method 1: Check for output files (most reliable)
            output_results = self._read_tool_results(tool_name, command)
            if output_results:
                return {
                    "completed": True,
                    "failed": False,
                    "results": output_results,
                    "method": "output_file_detection",
                    "status": "Tool completed - results found in output files"
                }
            
            # Special handling for nikto - it might complete without obvious output files
            if tool_name.lower() == "nikto":
                # Check for nikto-specific completion indicators
                nikto_completion = self._check_nikto_completion()
                if nikto_completion["completed"]:
                    # Try to read results again
                    final_results = self._read_tool_results(tool_name, command)
                    return {
                        "completed": True,
                        "failed": False,
                        "results": final_results,
                        "method": "nikto_completion_detection",
                        "status": "Nikto completed - detected completion indicators"
                    }
            
            # Method 2: Check if terminal is still running (process-based detection)
            terminal_status = self._check_terminal_running_status(tool_name)
            if not terminal_status["running"]:
                # Terminal closed - tool completed
                if terminal_status["completed_normally"]:
                    # Try one more time to read results
                    final_results = self._read_tool_results(tool_name, command)
                    if final_results:
                        return {
                            "completed": True,
                            "failed": False,
                            "results": final_results,
                            "method": "terminal_closed_with_results",
                            "status": "Tool completed - terminal closed and results captured"
                        }
                    else:
                        return {
                            "completed": False,
                            "failed": True,
                            "results": "",
                            "method": "terminal_closed_no_results",
                            "status": "Tool completed but no results captured",
                            "failure_reason": "Terminal closed without producing results"
                        }
                else:
                    return {
                        "completed": False,
                        "failed": True,
                        "results": "",
                        "method": "terminal_closed_abnormally",
                        "status": "Tool execution failed - terminal closed abnormally",
                        "failure_reason": "Terminal closed unexpectedly"
                    }
            
            # Method 3: Check for tool-specific completion indicators
            completion_indicators = self._check_tool_completion_indicators(tool_name)
            if completion_indicators["completed"]:
                # Tool shows completion indicators
                final_results = self._read_tool_results(tool_name, command)
                return {
                    "completed": True,
                    "failed": False,
                    "results": final_results,
                    "method": "completion_indicators",
                    "status": "Tool completed - detected completion indicators"
                }
            
            # Method 4: Check if tool execution failed
            if self._is_tool_execution_failed(tool_name):
                return {
                    "completed": False,
                    "failed": True,
                    "results": "",
                    "method": "execution_failure_detection",
                    "status": "Tool execution failed",
                    "failure_reason": "Tool failed to execute or crashed"
                }
            
            # Tool is still running
            return {
                "completed": False,
                "failed": False,
                "results": "",
                "method": "still_running",
                "status": f"Tool {tool_name} is still running"
            }
            
        except Exception as e:
            logger.error(f"[ExternalToolExecutor] Error checking tool completion: {str(e)}")
            return {
                "completed": False,
                "failed": True,
                "results": "",
                "method": "error_during_check",
                "status": f"Error checking completion: {str(e)}",
                "failure_reason": f"Error during completion check: {str(e)}"
            }
    
    def _check_terminal_running_status(self, tool_name: str) -> Dict[str, any]:
        """
        Check if terminal is still running for a specific tool.
        
        Parameters:
            tool_name: Name of the tool
            
        Returns:
            Dictionary with terminal status
        """
        try:
            if platform.system().lower() == "darwin":  # macOS
                applescript = f'''
                tell application "Terminal"
                    set windowCount to count of windows
                    repeat with i from 1 to windowCount
                        set windowName to name of window i
                        if windowName contains "{tool_name}" or windowName contains "TOOL_EXECUTION_COMPLETE" then
                            return "running"
                        end if
                    end repeat
                    return "closed"
                end tell
                '''
                result = subprocess.run(["osascript", "-e", applescript], 
                                     capture_output=True, text=True, check=False)
                
                if result.stdout.strip() == "running":
                    return {
                        "running": True,
                        "completed_normally": False,
                        "status": "Terminal still running"
                    }
                else:
                    return {
                        "running": False,
                        "completed_normally": True,  # Assume normal completion
                        "status": "Terminal closed"
                    }
                    
            elif platform.system().lower() == "windows":  # Windows
                try:
                    import psutil
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        try:
                            if proc.info['name'] == 'cmd.exe' and proc.info['cmdline']:
                                cmd_line = ' '.join(proc.info['cmdline'])
                                if tool_name.lower() in cmd_line.lower():
                                    return {
                                        "running": True,
                                        "completed_normally": False,
                                        "status": "Command prompt still running"
                                    }
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    
                    return {
                        "running": False,
                        "completed_normally": True,
                        "status": "Command prompt closed"
                    }
                except ImportError:
                    return {
                        "running": False,
                        "completed_normally": True,
                        "status": "Command prompt status unknown (psutil not available)"
                    }
                    
            else:  # Linux
                try:
                    import psutil
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        try:
                            if proc.info['name'] in ['xterm', 'gnome-terminal', 'konsole', 'terminator']:
                                cmd_line = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                                if tool_name.lower() in cmd_line.lower():
                                    return {
                                        "running": True,
                                        "completed_normally": False,
                                        "status": "Terminal still running"
                                    }
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    
                    return {
                        "running": False,
                        "completed_normally": True,
                        "status": "Terminal closed"
                    }
                except ImportError:
                    return {
                        "running": False,
                        "completed_normally": True,
                        "status": "Terminal status unknown (psutil not available)"
                    }
                    
        except Exception as e:
            logger.warning(f"[ExternalToolExecutor] Error checking terminal status: {str(e)}")
            return {
                "running": False,
                "completed_normally": False,
                "status": f"Error checking terminal status: {str(e)}"
            }
    
    def _check_nikto_completion(self) -> Dict[str, any]:
        """
        Special completion detection for nikto tool.
        
        Returns:
            Dictionary with nikto completion status
        """
        try:
            # Check for nikto output file
            if os.path.exists("nikto_scan.txt"):
                # Check if file has content and is not empty
                try:
                    with open("nikto_scan.txt", "r") as f:
                        content = f.read().strip()
                        if content and len(content) > 100:  # Nikto output should be substantial
                            return {
                                "completed": True,
                                "status": "Nikto scan completed with results",
                                "file": "nikto_scan.txt",
                                "content_length": len(content)
                            }
                except Exception as e:
                    logger.debug(f"[ExternalToolExecutor] Error reading nikto output: {str(e)}")
            
            # Check for nikto process completion patterns
            # Nikto typically shows completion messages in terminal
            return {
                "completed": False,
                "status": "Nikto still running or no substantial output yet"
            }
            
        except Exception as e:
            logger.error(f"[ExternalToolExecutor] Error checking nikto completion: {str(e)}")
            return {
                "completed": False,
                "status": f"Error: {str(e)}"
            }

    def _check_tool_completion_indicators(self, tool_name: str) -> Dict[str, any]:
        """
        Check for tool-specific completion indicators.
        
        Parameters:
            tool_name: Name of the tool
            
        Returns:
            Dictionary with completion indicator status
        """
        try:
            # Check for completion indicator files
            completion_files = [
                f"{tool_name}_completed.txt",
                f"{tool_name}_done.txt",
                f"{tool_name}_finished.txt"
            ]
            
            for filename in completion_files:
                if os.path.exists(filename):
                    return {
                        "completed": True,
                        "method": "completion_file",
                        "status": f"Found completion indicator: {filename}"
                    }
            
            # Check for specific tool completion patterns
            if tool_name.lower() == "nmap":
                # Nmap typically creates .xml or .txt files when complete
                nmap_files = glob.glob("nmap*.xml") + glob.glob("nmap*.txt")
                if nmap_files:
                    return {
                        "completed": True,
                        "method": "nmap_output_files",
                        "status": f"Found nmap output files: {nmap_files}"
                    }
            
            elif tool_name.lower() == "gobuster":
                # Gobuster typically shows completion message in output
                # We'll rely on terminal status for this tool
                pass
            
            elif tool_name.lower() == "sqlmap":
                # SQLMap creates detailed output directories
                sqlmap_dirs = glob.glob("sqlmap_output*")
                if sqlmap_dirs:
                    return {
                        "completed": True,
                        "method": "sqlmap_output_directory",
                        "status": f"Found sqlmap output directory: {sqlmap_dirs}"
                    }
            
            # No completion indicators found
            return {
                "completed": False,
                "method": "no_indicators",
                "status": "No completion indicators found"
            }
            
        except Exception as e:
            logger.warning(f"[ExternalToolExecutor] Error checking completion indicators: {str(e)}")
            return {
                "completed": False,
                "method": "error_checking_indicators",
                "status": f"Error checking indicators: {str(e)}"
            }
