import os
import json
import time
import threading
import queue
import base64
import logging
import textwrap
import re
import shutil
import random
import sqlite3
import nest_asyncio
import asyncio
import atexit
from urllib.parse import urlparse
from tqdm import tqdm
import hashlib
from utils.logger import Logger
from network.proxy import WebProxy
from llm.llm import LLM
from core.scanner import PageAnalyzer
from utils.html_parser import HTMLParser
from core.planner import AttackStrategyGenerator
from core.tools import BrowserActionExecutor
from reporting.summarizer import Summarizer
from utils.utils import check_hostname, enumerate_subdomains, count_tokens
from typing import List, Dict, Union, Optional
from reporting.reporter import Reporter
from utils.constants import OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY
from rich.progress import Progress  # Ensure this import is present if using rich.progress

# Multi-model collaboration support
try:
    from llm.multi_model_llm import MultiModelLLM, ModelRole
    MULTI_MODEL_AVAILABLE = True
except ImportError:
    MULTI_MODEL_AVAILABLE = False
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.style import Style
from rich.progress import Progress, TextColumn, BarColumn, TimeRemainingColumn
from rich.text import Text
from rich.layout import Layout
from rich.progress import SpinnerColumn, TimeElapsedColumn

from google import genai
from google.genai import types

# Allow nested event loops
nest_asyncio.apply()

logger = Logger()
console = Console()

logging.basicConfig(level=logging.INFO)
std_logger = logging.getLogger(__name__)

# --- Hacker-style progress helpers ---

def _hacker_status(iteration: int, max_iter: int, tool: Optional[str] = None) -> str:
    phrases = [
        "INIT VECTOR", "BRUTE SIG", "FUZZ PAYLOAD", "EVAL RESPONSE",
        "ESC LAYER", "SQLi PROBE", "XSS VECTOR", "LFI TRACE",
        "COOKIE SNIFF", "JWT TAMPER", "CSP BYPASS", "HEADERS DUMP"
    ]
    phase = random.choice(phrases)
    tool_txt = tool if tool else "LLM"
    return f"{phase} • step {iteration}/{max_iter} • tool={tool_txt}"


def _create_hacker_progress(attacker_ip: str, target_ip: str, target_port: int) -> Progress:
    columns = [
        TextColumn("[bold red]» HACKNET «[/bold red]", justify="left"),
        SpinnerColumn(style="bold red"),
        TextColumn(f"[cyan]{attacker_ip}[/] -> [magenta]{target_ip}:{target_port}[/]"),
        BarColumn(bar_width=None, style="bright_magenta", complete_style="bold green",
                  finished_style="green", pulse_style="bright_magenta"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        TextColumn("[yellow]{task.description}[/yellow]", justify="right"),
    ]
    return Progress(*columns, expand=True, transient=False)

# def print_double_box(title: str, logger, length=120, color='light_cyan'):
#     padding = (length - len(title)) // 2
#     title_line = f"║{' ' * padding}{title}{' ' * (length - len(title) - padding)}║"
#     logger.info("╔" + "═" * length + "╗", color=color)
#     logger.info(title_line, color=color)
#     logger.info("╚" + "═" * length + "╝", color=color)

# def print_boxed_block(title, content, logger, color='light_cyan', padding=2, max_width=122):
#     terminal_width = shutil.get_terminal_size((max_width, 20)).columns
#     box_width = min(max_width, terminal_width - 2)
#     inner_width = box_width - 2
#     wrap_width = inner_width - (padding * 2)

#     def format_paragraphs(raw_text):
# # If contains paragraph tags, process in segments
#         if "* " in raw_text:
#             sections = re.split(r"\* (\w+)", raw_text)
#             result_lines = []
#             i = 1
#             while i < len(sections):
#                 header = sections[i].strip().upper()
#                 body = sections[i+1].strip()
#                 result_lines.append(f"* {header}")
#                 for line in textwrap.wrap(body, width=wrap_width):
#                     result_lines.append(line)
#                 result_lines.append("")
#                 i += 2
#             return result_lines
#         else:
# # Single segment processing (default: pure content without DISCUSSION, ACTION)
#             return textwrap.wrap(raw_text.strip(), width=wrap_width)

#     lines = format_paragraphs(content)

#     # top border
#     logger.info("┌" + "─" * inner_width + "┐", color=color)

#     # title
#     if title:
#         centered_title = f" {title} ".center(inner_width)
#         logger.info(f"│{centered_title}│", color=color)
#         logger.info("├" + "─" * inner_width + "┤", color=color)

#     # content
#     for line in lines:
#         padded = " " * padding + line.ljust(wrap_width) + " " * padding
#         logger.info(f"│{padded}│", color=color)

#     # bottom border
#     logger.info("└" + "─" * inner_width + "┘", color=color)
    
console = Console()


import textwrap

def wrap_text_preserve_words(text: str, width: int = 100) -> str:
    """
    Wrap text to the specified width without splitting words.
    
    Parameters:
        text: The input text to wrap
        width: The maximum width of each line
        
    Returns:
        Wrapped text as a single string with newlines
    """
    # Split the text into lines (if it contains newlines)
    lines = text.split('\n')
    wrapped_lines = []
    
    for line in lines:
        # Use textwrap to wrap the line without splitting words
        wrapped = textwrap.wrap(line, width=width, break_long_words=False, replace_whitespace=False)
        wrapped_lines.extend(wrapped)
    
    # Join the wrapped lines with newlines
    return '\n'.join(wrapped_lines)

def print_hacker_header(title: str, logger, length=100, color='green'):
    jargon = random.choice([
        "ESTABLISHING SECURE CONNECTION...",
        "BYPASSING FIREWALL PROTOCOLS...",
        "ENCRYPTING DATA_STREAM...",
        "INITIALIZING HACKNET PROTOCOL...",
        "PINGING DARKNET RELAY..."
    ])
    glitch_title = f"[glitch]{title.upper()}[/glitch]"
    accent = ">>> [HACKNET v2.3] >>>"
    console.print(f"[bold cyan]{jargon}[/bold cyan]")
    console.print(f"[bold {color}]{accent} {glitch_title} #[/bold {color}]")
    console.print(f"[bold {color}]{'=' * length}[/bold {color}]")
    console.print(f"[dim]CONN: {random.randint(1000, 9999)}ms | UPLINK: {random.randint(50, 200)}Mbps[/dim]")


import socket
def get_attacker_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        attacker_ip = s.getsockname()[0]
        s.close()
        return attacker_ip
    except Exception:
        return "127.0.0.1"

def get_target_ip_and_port(url: str):
    """Resolve the target IP and port from the given URL."""
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        target_ip = socket.gethostbyname(hostname)
        return target_ip, port
    except Exception as e:
        logger.error(f"Failed to resolve target IP for {url}: {str(e)}")
        return "unknown.target", port


def _retry_llm_reason(llm, history, logger, max_retries=3, retry_delay=60):
    """
    Helper function to retry llm.reason on quota errors.

    Parameters:
        llm: The LLM instance to call.
        history (list): The conversation history for the LLM call.
        logger: The logger instance.
        max_retries (int): Maximum number of retry attempts.
        retry_delay (int): Delay in seconds between retries.

    Returns:
        str: The LLM response.

    Raises:
        Exception: If all retries fail.
    """
    for attempt in range(max_retries):
        try:
            response = llm.reason(history)
            return response
        except Exception as e:
            if "google.api_core.exceptions.ResourceExhausted" in str(type(e)) and "quota" in str(e).lower():
                logger.info(f"Quota limit exceeded in print_hacker_output (attempt {attempt + 1}/{max_retries}). Waiting {retry_delay} seconds to resume...", color='yellow')
                time.sleep(retry_delay)
                continue
            else:
                logger.error(f"Error during LLM summarization in print_hacker_output: {str(e)}", color='red')
                raise
    raise Exception(f"Failed to complete LLM summarization in print_hacker_output after {max_retries} attempts due to quota limits.")

def print_hacker_output(title: str, content: str, logger, color='green', max_width=200, target_ip=None, target_port=None, ai_process=None, llm=None, hide_ip=False):
    logger.debug(f"[print_hacker_output] Called with title: {title}, color: {color}, content: {content[:5000]}...")
    
    terminal_width = min(shutil.get_terminal_size((max_width, 20)).columns, max_width)
    # Adjust wrap widths for both panels
    findings_wrap_width = (terminal_width * 2 // 5) - 10  # Left panel takes ~2/5 of the terminal width
    ai_process_wrap_width = (terminal_width * 3 // 5) - 15  # Right panel takes ~3/5 of the terminal width

    attacker_ip = get_attacker_ip()
    dst_ip = target_ip if target_ip else "unknown.target"
    dst_port = target_port if target_port else 80

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    # Check if the content is meaningful (e.g., not just a generic error)
    def is_meaningful_content(text: str) -> bool:
        uninformative_patterns = [
            r"execution failed: 'selector'",
            r"failed to.*timeout",
            r"no elements found",
            r"locator.*not found",
        ]
        is_uninformative = any(re.search(pattern, text.lower()) for pattern in uninformative_patterns)
        meaningful_keywords = [
            "vulnerability", "xss", "sql injection", "sensitive data", "exposed",
            "admin", "endpoint", "server response", "http header", "status code",
            "successful", "exploit", "discovered", "accessed", "outdated"
        ]
        has_meaningful_content = any(keyword in text.lower() for keyword in meaningful_keywords)
        return not is_uninformative or has_meaningful_content

    # If content is uninformative, provide a fallback message
    if not is_meaningful_content(content):
        logger.debug(f"[print_hacker_output] Skipping uninformative content for {title}: {content}")
        summarized_content = "* SUMMARY\nNo significant findings yet. Continuing analysis..."
    else:
        summarized_content = content

    # Summarize the content using AI if it's detailed
    if llm and ("NETWORK TRAFFIC" in title.upper() or "ATTACK EXECUTION" in title.upper() or "RESPONSE" in title.upper()):
        summary_prompt = f"""
        Summarize the following detailed output into key points (2-3 sentences max). Focus on meaningful security findings, such as discovered vulnerabilities, interesting server responses, or notable discoveries (e.g., exposed endpoints, successful exploits, outdated software). Avoid including generic errors (e.g., "Execution failed: 'selector'") unless they lead to a significant outcome:

        {content}

        Provide your summary in the following format:
        * SUMMARY
        [Your concise summary of the key points, focusing on significant security findings.]
        """
        history = [
            {"role": "system", "content": "You are a security analysis assistant tasked with summarizing detailed logs into meaningful security findings."},
            {"role": "user", "content": summary_prompt}
        ]
        summarized_content = _retry_llm_reason(llm, history, logger)
        if not is_meaningful_content(summarized_content):
            logger.debug(f"[print_hacker_output] Summarized content is uninformative for {title}: {summarized_content}")
            summarized_content = "* SUMMARY\nNo significant findings yet. Continuing analysis..."

    # Enhanced hacker-style formatting with glitch effect and AI thinking visualization
    def format_hacker_text(raw_text, wrap_width, is_ai_process=False, max_lines=None):
        lines = []
        # Handle IP display based on hide_ip flag
        if hide_ip:
            prefix = f"[HACKNET] [HIDDEN] -> {dst_ip}:{dst_port}"
        else:
            prefix = f"[HACKNET] {attacker_ip} -> {dst_ip}:{dst_port}"
        
        # Enhanced hacker-style elements
        hacker_symbols = ["⚡", "🔒", "💻", "🌐", "🎯", "🚨", "💡", "🔍", "⚔️", "🛡️"]
        current_symbol = random.choice(hacker_symbols)
        
        # Remove duplicate lines and redundant headers
        seen_lines = set()
        seen_headers = set()
        if "* " in raw_text:
            sections = re.split(r"\* (\w+)", raw_text)
            i = 1
            while i < len(sections):
                header = sections[i].strip().upper()
                body = sections[i + 1].strip()
                
                # Enhanced header formatting with hacker symbols
                if header not in seen_headers or not is_ai_process:
                    seen_headers.add(header)
                    if is_ai_process:
                        # AI thinking process gets special formatting
                        if "DISCUSSION" in header:
                            symbol = "🧠"
                            style = "bold magenta"
                        elif "ACTION" in header:
                            symbol = "⚔️"
                            style = "bold red"
                        elif "ANALYSIS" in header:
                            symbol = "🔍"
                            style = "bold cyan"
                        elif "STRATEGY" in header:
                            symbol = "🎯"
                            style = "bold yellow"
                        else:
                            symbol = current_symbol
                            style = "bold cyan"
                        
                        glitch_header = f"[glitch]{symbol} {header}[/glitch]"
                        lines.append(Text(f"{prefix} | {glitch_header}", style=style))
                        
                        # Add AI thinking process indicators
                        if "DISCUSSION" in header:
                            lines.append(Text(f"  [AI_THINKING] Processing attack strategy...", style="dim cyan"))
                        elif "ACTION" in header:
                            lines.append(Text(f"  [AI_EXECUTION] Executing attack plan...", style="dim red"))
                    else:
                        glitch_header = f"[glitch]{current_symbol} {header}[/glitch]"
                        lines.append(Text(f"{prefix} | {glitch_header}", style="bold cyan"))
                elif is_ai_process:
                    # For AI process, add a separator between sections
                    lines.append(Text("  " + "─" * 20, style="dim"))

                paragraphs = body.split('\n')
                for para in paragraphs:
                    if para.strip():
                        wrapped_lines = textwrap.wrap(para.strip(), width=wrap_width, replace_whitespace=False)
                        for line in wrapped_lines:
                            if line not in seen_lines:
                                seen_lines.add(line)
                                # Enhanced line formatting with context indicators
                                if is_ai_process:
                                    if "vulnerability" in line.lower() or "exploit" in line.lower():
                                        prefix_symbol = "🚨"
                                        style = "bright_red"
                                    elif "test" in line.lower() or "scan" in line.lower():
                                        prefix_symbol = "🔍"
                                        style = "bright_yellow"
                                    elif "success" in line.lower() or "found" in line.lower():
                                        prefix_symbol = "✅"
                                        style = "bright_green"
                                    elif "error" in line.lower() or "fail" in line.lower():
                                        prefix_symbol = "❌"
                                        style = "bright_red"
                                    else:
                                        prefix_symbol = "💭"
                                        style = "bright_green"
                                    
                                    lines.append(Text(f"  {prefix_symbol} {line}", style=style))
                                else:
                                    lines.append(Text(f"  >>> {line}", style="bright_green"))
                    else:
                        lines.append(Text(""))
                i += 2
        else:
            wrapped_lines = textwrap.wrap(raw_text.strip(), width=wrap_width)
            for line in wrapped_lines:
                if line not in seen_lines:
                    seen_lines.add(line)
                    lines.append(Text(f"  >>> {line}", style="bright_green"))

        # Truncate lines if max_lines is specified (for SYSTEM LOG panel)
        if max_lines and len(lines) > max_lines:
            lines = lines[-max_lines:]  # Keep only the last max_lines
            lines.insert(0, Text("  ... (older logs truncated)", style="dim"))

        return lines

    # Prepare the main content (left panel: findings)
    ascii_headers = [
        """
┌──[ HACKNET v2.3 ]──┐
│  INTRUSION DETECT  │
└────────────────────┘
""",
        """
┌──[ HACKNET v2.3 ]──┐
│   SYSTEM BREACH    │
└────────────────────┘
""",
        """
┌──[ HACKNET v2.3 ]──┐
│  TARGET ACQUIRED   │
└────────────────────┘
"""
    ]
    ascii_header = random.choice(ascii_headers)
    # Ensure the header fits within the panel width
    header_width = findings_wrap_width + 10
    header_lines = ascii_header.strip().split('\n')
    adjusted_header_lines = []
    for line in header_lines:
        if len(line) > header_width:
            line = line[:header_width - 3] + "┘" if "┘" in line else line[:header_width]
        else:
            line = line.center(header_width)
        adjusted_header_lines.append(line)
    adjusted_header = '\n'.join(adjusted_header_lines)

    header = Text(adjusted_header, style="bold magenta")
    glitch_title = f"[glitch]{title.upper()}[/glitch]"
    header.append(f"\n[{timestamp}] {glitch_title}\n", style="bold red")

    main_content = Text()
    main_content.append(header)
    main_lines = format_hacker_text(summarized_content, wrap_width=findings_wrap_width)

    for line in main_lines:
        main_content.append(line)
        main_content.append("\n")

    # Calculate the required height for the findings panel
    findings_height = len(main_content.split()) + 2

    # Prepare the AI process content (right panel)
    ai_content = Text()
    max_ai_lines = 25  # Increased from 15 to show much more AI thinking process
    if ai_process:
        ai_content.append(f"[glitch]🤖 AI THINKING PROCESS[/glitch]\n", style="bold yellow")
        
        # Enhanced AI process display with better formatting
        ai_lines = format_hacker_text(ai_process, wrap_width=ai_process_wrap_width, is_ai_process=True, max_lines=max_ai_lines)
        
        # Add visual separators and better formatting for AI sections
        formatted_ai_content = Text()
        current_section = ""
        
        for line in ai_lines:
            line_text = line.plain if hasattr(line, 'plain') else str(line)
            
            # Detect section headers (lines starting with *)
            if line_text.strip().startswith('*'):
                current_section = line_text.strip()
                # Add section header with special formatting
                formatted_ai_content.append(f"\n[bold cyan]🔍 {current_section}[/bold cyan]\n", style="bold cyan")
            elif line_text.strip() and not line_text.strip().startswith('>>>'):
                # Regular content line
                formatted_ai_content.append(f"  {line_text}\n", style="bright_green")
            elif line_text.strip().startswith('>>>'):
                # AI thinking content
                formatted_ai_content.append(f"{line_text}\n", style="bright_green")
            else:
                # Empty line or separator
                formatted_ai_content.append(line)
                formatted_ai_content.append("\n")
        
        ai_content.append(formatted_ai_content)
        
        # Add AI thinking status indicator
        ai_content.append(f"\n[bold yellow]📊 AI THINKING STATUS[/bold yellow]\n", style="bold yellow")
        ai_content.append(f"  🧠 Active Thinking: {time.strftime('%Y-%m-%d %H:%M:%S')}\n", style="bright_green")
        ai_content.append(f"  📝 Content Lines: {len(ai_lines)}/{max_ai_lines}\n", style="bright_green")
        ai_content.append(f"  🔄 Process Active: Yes\n", style="bright_green")
    else:
        ai_content.append("[dim]No AI thinking process available yet...[/dim]\n", style="dim")

    # Calculate the required height for the ai_process panel
    ai_process_height = min(len(ai_content.split()) + 2, max_ai_lines + 2) if ai_process else 3

    # Synchronize heights to ensure both panels align vertically, but cap the maximum height
    max_height = max(findings_height, ai_process_height)
    max_height = min(max_height, 30)  # Increased from 15 to 30 to show more content

    # Create the split-panel layout with adjusted ratios and synchronized heights
    layout = Layout()
    layout.split_row(
        Layout(name="findings", ratio=2, minimum_size=max_height),
        Layout(name="ai_process", ratio=3, minimum_size=max_height)
    )

    layout["findings"].update(Panel(main_content, border_style="red", title="[glitch]INTRUSION[/glitch]", height=max_height, width=findings_wrap_width + 15))
    layout["ai_process"].update(Panel(ai_content if ai_process else "No AI process data available.", border_style="cyan", title="[glitch]SYSTEM LOG[/glitch]", height=max_height, width=ai_process_wrap_width + 20))

    # Add a cinematic touch with a top border
    console.print(f"[bold red]// HACKNET v2.3 - INTRUSION PROTOCOL ACTIVE {'=' * (terminal_width - 40)}[/bold red]")
    console.print(layout)
    console.print(f"[bold red]{'=' * terminal_width}[/bold red]")

    # # Log the summarized content
    # logger.info(f"[{title}]")
    # for line in main_lines:
    #     logger.info(line.plain)


def print_hacker_terminal(title: str, content: str, logger, color='green', max_width=100):
    terminal_width = min(shutil.get_terminal_size((max_width, 20)).columns, max_width)
    wrap_width = max(terminal_width - 10, 20)
    
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    def format_hacker_text(raw_text):
        lines = []
        if "* " in raw_text:
            sections = re.split(r"\* (\w+)", raw_text)
            i = 1
            while i < len(sections):
                header = sections[i].strip().upper()
                body = sections[i + 1].strip()
                lines.append(f"[root@hacknet] # {header}")
                paragraphs = body.split('\n')
                for para in paragraphs:
                    if para.strip():
                        wrapped_lines = textwrap.wrap(para.strip(), width=wrap_width, replace_whitespace=False)
                        for line in wrapped_lines:
                            lines.append(f"  > {line}")
                    else:
                        lines.append("")
                i += 2
        else:
            wrapped_lines = textwrap.wrap(raw_text.strip(), width=wrap_width)
            for line in wrapped_lines:
                lines.append(f"  > {line}")
        return lines

    lines = format_hacker_text(content)

    glitch_title = f"[glitch]{title.upper()}[/glitch]"
    console.print(f"[bold cyan][{timestamp}] // HACKNET v2.3 - {glitch_title} #[/bold cyan]")
    for line in lines:
        console.print(f"[bold {color}]{line}[/bold {color}]")
    console.print(f"[bold {color}]---[/bold {color}]")

def print_hacker_double_box(title: str, logger, length=100, color='green'):
    glitch_title = f"[glitch]{title}[/glitch]"
    console.print(f"[bold {color}]// SYSLOG [{glitch_title}] #[/bold {color}]")
    console.print(f"[bold {color}]{'=' * length}[/bold {color}]")


#ef print_boxed_block(title, content, logger, color='light_cyan', padding=2, max_width=122):
# Duplicate imports removed - already imported at top of file
from rich.progress import Progress
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.style import Style
from rich.progress import TextColumn, BarColumn, TimeRemainingColumn
from rich.text import Text
from rich.layout import Layout
from rich.progress import SpinnerColumn, TimeElapsedColumn

import socket
import hashlib

# Allow nested event loops
nest_asyncio.apply()

logger = Logger()
console = Console()

logging.basicConfig(level=logging.INFO)
std_logger = logging.getLogger(__name__)

# --- Hacker-style progress helpers ---

def _hacker_status(iteration: int, max_iter: int, tool: Optional[str] = None) -> str:
    phrases = [
        "INIT VECTOR", "BRUTE SIG", "FUZZ PAYLOAD", "EVAL RESPONSE",
        "ESC LAYER", "SQLi PROBE", "XSS VECTOR", "LFI TRACE",
        "COOKIE SNIFF", "JWT TAMPER", "CSP BYPASS", "HEADERS DUMP"
    ]
    phase = random.choice(phrases)
    tool_txt = tool if tool else "LLM"
    return f"{phase} • step {iteration}/{max_iter} • tool={tool_txt}"

def _create_hacker_progress(attacker_ip: str, target_ip: str, target_port: int) -> Progress:
    columns = [
        TextColumn("[bold red]» HACKNET «[/bold red]", justify="left"),
        SpinnerColumn(style="bold red"),
        TextColumn(f"[cyan]{attacker_ip}[/] -> [magenta]{target_ip}:{target_port}[/]"),
        BarColumn(bar_width=None, style="bright_magenta", complete_style="bold green",
                  finished_style="green", pulse_style="bright_magenta"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        TextColumn("[yellow]{task.description}[/yellow]", justify="right"),
    ]
    return Progress(*columns, expand=True, transient=False)


def wrap_text_preserve_words(text: str, width: int = 100) -> str:
    lines = text.split('\n')
    wrapped_lines = []
    for line in lines:
        wrapped = textwrap.wrap(line, width=width, break_long_words=False, replace_whitespace=False)
        wrapped_lines.extend(wrapped)
    return '\n'.join(wrapped_lines)

def print_hacker_header(title: str, logger, length=100, color='green'):
    jargon = random.choice([
        "ESTABLISHING SECURE CONNECTION...", "BYPASSING FIREWALL PROTOCOLS...",
        "ENCRYPTING DATA_STREAM...", "INITIALIZING HACKNET PROTOCOL...", "PINGING DARKNET RELAY..."
    ])
    glitch_title = f"[glitch]{title.upper()}[/glitch]"
    accent = ">>> [HACKNET v2.3] >>>"
    console.print(f"[bold cyan]{jargon}[/bold cyan]")
    console.print(f"[bold {color}]{accent} {glitch_title} #[/bold {color}]")
    console.print(f"[bold {color}]{'=' * length}[/bold {color}]")
    console.print(f"[dim]CONN: {random.randint(1000, 9999)}ms | UPLINK: {random.randint(50, 200)}Mbps[/dim]")





class SecurityOrchestrator:
    """
    Core orchestrator for AI-powered web application security testing.
    
    Coordinates LLM-driven vulnerability analysis, test plan generation,
    and automated security validation using browser automation and
    network traffic monitoring.
    """

    def __init__(self, starting_url: str, expand_scope: bool = False, 
             enumerate_subdomains: bool = False, model: str = 'gpt-4o',
             provider: str = 'openai', output_dir: str = 'scan_output', 
             max_iterations: int = 30, debug: bool = False, target_ip=None, target_port=None,
             clear_attack_history: bool = False, wordlists_dir: str = 'lists', hide_ip: bool = False):
        self.starting_url = starting_url
        self.expand_scope = expand_scope
        self.should_enumerate_subdomains = enumerate_subdomains
        self.model = model
        self.provider = provider.lower()  # Keep provider lowercase
        self.model_provider = provider.lower()  # Add model_provider, keep consistent with provider
        # Accept ollama and litellm as valid providers
        if self.provider not in ["openai", "anthropic", "gemini", "ollama", "litellm"]:
            raise ValueError(f"Unsupported model provider: {self.provider}")
        self.output_dir = output_dir
        self.max_iterations = max_iterations
        self.keep_messages = 15
        self.debug = debug
        self.console = Console()
        self.proxy = WebProxy(starting_url, logger)
        
        # Check if multi-model collaboration is enabled via environment variables
        use_multi_model = os.getenv("USE_MULTI_MODEL", "false").lower() == "true"
        
        if use_multi_model and MULTI_MODEL_AVAILABLE:
            # Initialize multi-model system
            self.multi_model_llm = MultiModelLLM(debug=debug)
            self.llm = self.multi_model_llm.get_primary_model()
            if debug:
                model_info = self.multi_model_llm.get_model_info()
                logger.info(f"[Agent] Multi-model collaboration enabled with {len(model_info)} models", color='green')
                for name, info in model_info.items():
                    logger.info(f"  - {name}: {info['role']} ({info['provider']}/{info['model']})", color='cyan')
        else:
            # Use single model
            self.multi_model_llm = None
            self.llm = LLM(model_provider=self.provider, model_name=model, debug=debug)
        
        self.planner = AttackStrategyGenerator(model_provider=self.provider, model_name=model, debug=debug)
        self.scanner = None
        self.tools = BrowserActionExecutor(model_provider=self.provider, model_name=model, debug=debug)
        self.history = []
        self.target_ip = target_ip
        self.target_port = target_port
        self.hide_ip = hide_ip  # Add hide_ip attribute
        start_netloc = urlparse(starting_url).netloc
        parts = start_netloc.split('.')
        self.starting_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else start_netloc
        self.reporter = Reporter(starting_url, model_provider=self.provider, model_name=model, debug=debug)
        self.successful_attacks = []
        self.db_path = os.path.join(output_dir, "attack_log.db")
        self._setup_database()
        if clear_attack_history:
            self._clear_attacked_urls()
        
        # Initialize AI tool detector and wordlist manager
        self.project_root = os.getcwd()  # Set project root
        self.wordlists_dir = wordlists_dir  # Set wordlists directory
        self.ai_tool_detector = None
        self.wordlist_manager = None
        self._init_ai_components()
        
        self.generation_config = {"temperature": 7, "top_p": 0.95, "top_k": 64, "max_output_tokens": 8192}
        self.safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ]
        self.gemini_request_count = 0
        self.last_reset_time = time.time()
        self.gemini_rpm_limit = 15
        self.gemini_rpm_window = 60
        self.llm_lock = threading.Lock()
        logger.debug("[Agent.__init__] Agent initialized with Tools instance")
        if self.provider == "ollama":
            logger.info(f"[LLM] Using Ollama local provider with model: {model}", color='green')
    
    def _init_ai_components(self):
        """Initialize AI tool detector, wordlist manager, and AI security testing components."""
        try:
            from tools.ai_tool_detector import AIToolDetector
            from tools.wordlist_manager import WordlistManager
            from detection.ai_chatbot_detector import AIChatbotDetector
            from detection.ai_service_fingerprinter import AIServiceFingerprinter
            from testing.prompt_injection_tester import PromptInjectionTester
            from testing.rag_system_tester import RAGSystemTester
            from analysis.ai_vulnerability_classifier import AIVulnerabilityClassifier
            from analysis.ai_response_analyzer import AIResponseAnalyzer
            
            self.ai_tool_detector = AIToolDetector(
                self.project_root, 
                self.wordlists_dir, 
                self.starting_url,
                db_callback=self.save_external_tool_execution
            )
            self.wordlist_manager = WordlistManager(self.project_root, self.wordlists_dir)
            
            # Initialize AI Chatbot security testing components
            self.ai_chatbot_detector = AIChatbotDetector()
            self.ai_service_fingerprinter = AIServiceFingerprinter()
            self.prompt_injection_tester = PromptInjectionTester()
            self.rag_system_tester = RAGSystemTester()
            self.ai_vulnerability_classifier = AIVulnerabilityClassifier()
            self.ai_response_analyzer = AIResponseAnalyzer()
            
            logger.info("[Agent._init_ai_components] AI components initialized successfully", color='green')
            
            # Display available tools and wordlists
            if self.ai_tool_detector:
                available_tools = self.ai_tool_detector.get_available_tools()
                logger.info(f"[Agent._init_ai_components] Available external tools: {len(available_tools)}", color='cyan')
                for tool in available_tools:
                    logger.info(f"  - {tool['tool_name']}: {tool['description']}", color='cyan')
            
            if self.wordlist_manager:
                stats = self.wordlist_manager.get_wordlist_stats()
                logger.info(f"[Agent._init_ai_components] Wordlist stats: {stats['total_wordlists']} wordlists, {stats['total_entries']:,} entries", color='cyan')
            
            logger.info("[Agent._init_ai_components] AI Chatbot security testing components initialized", color='green')
                
        except ImportError as e:
            logger.warning(f"[Agent._init_ai_components] Failed to import AI components: {str(e)}", color='yellow')
            # Set to None if import fails
            self.ai_chatbot_detector = None
            self.ai_service_fingerprinter = None
            self.prompt_injection_tester = None
            self.rag_system_tester = None
            self.ai_vulnerability_classifier = None
            self.ai_response_analyzer = None
        except Exception as e:
            logger.error(f"[Agent._init_ai_components] Error initializing AI components: {str(e)}", color='red')
            # Set to None on error
            self.ai_chatbot_detector = None
            self.ai_service_fingerprinter = None
            self.prompt_injection_tester = None
            self.rag_system_tester = None
            self.ai_vulnerability_classifier = None
            self.ai_response_analyzer = None

    def clear_database(self):
        """Clear all entries in the error_logs and attacks tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM error_logs")
        cursor.execute("DELETE FROM attacks")
        conn.commit()
        conn.close()
        logger.info("[Agent] Database cleared: all attack history and error logs removed", color='yellow')
    
    def _setup_database(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                plan_title TEXT,
                plan_description TEXT,
                execution_log TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS error_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level TEXT,
                message TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attack_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                plan_title TEXT,
                plan_description TEXT,
                history TEXT,
                iterations INTEGER,
                total_plans INTEGER,
                plan_index INTEGER,
                ai_process TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tool_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                plan_title TEXT,
                llm_response TEXT,
                tool_use TEXT,
                tool_output TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attacked_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                url_hash TEXT UNIQUE,
                page_content_hash TEXT,
                attack_count INTEGER DEFAULT 1,
                last_attack_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS external_tool_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool_name TEXT,
                target_url TEXT,
                command TEXT,
                parameters TEXT,
                execution_result TEXT,
                success BOOLEAN,
                execution_time REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()
        
    def _clear_error_logs(self):
        self.clear_database()

        
    def _save_attack_state(self, url, plan, history, iterations, total_plans, plan_index, ai_process):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        history_json = json.dumps(history)
        cursor.execute("""
            INSERT INTO attack_state (url, plan_title, plan_description, history, iterations, total_plans, plan_index, ai_process)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (url, plan['title'], plan.get('description', ''), history_json, iterations, total_plans, plan_index, ai_process))
        conn.commit()
        conn.close()
        
    def _generate_enhanced_section(self, section_type, content, page, url, iterations):
        """Generate enhanced section with better context and analysis."""
        try:
            # Get current page context
            page_title = page.title if hasattr(page, 'title') else "Unknown Page"
            current_url = page.url
            
            # Generate enhanced section based on type
            if section_type == "DISCUSSION & ACTION":
                enhanced_content = f"""* 🧠 {section_type}
{content}

* 🔍 CONTEXT UPDATE
- Current Page: {page_title}
- URL: {current_url}
- Iteration: {iterations + 1}
- Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}

* 💭 THINKING PROCESS
I am analyzing the current situation and planning my next move:
1. What did I just do?
2. What was the result?
3. What should I do next?
4. What tools would be most effective?

* 🎯 NEXT STEPS
Based on my analysis, I will now proceed with the most appropriate security testing approach."""
            
            elif section_type == "RESPONSE":
                enhanced_content = f"""* 📡 {section_type}
{content}

* 🔍 RESPONSE ANALYSIS
- Page: {page_title}
- URL: {current_url}
- Iteration: {iterations + 1}
- Time: {time.strftime('%Y-%m-%d %H:%M:%S')}

* 💡 INSIGHTS
I need to analyze this response for:
1. Security vulnerabilities
2. Error messages that reveal information
3. Success indicators
4. Next attack opportunities

* 🚀 STRATEGY ADAPTATION
Based on this response, I will adjust my approach accordingly."""
            
            elif section_type == "NETWORK TRAFFIC":
                enhanced_content = f"""* 🌐 {section_type}
{content}

* 🔍 TRAFFIC ANALYSIS
- Page: {page_title}
- URL: {current_url}
- Iteration: {iterations + 1}
- Time: {time.strftime('%Y-%m-%d %H:%M:%S')}

* 📊 MONITORING INSIGHTS
I am monitoring network activity for:
1. Unusual traffic patterns
2. Security headers
3. Authentication flows
4. Potential vulnerabilities

* 🎯 SECURITY ASSESSMENT
This traffic analysis helps me understand the target's security posture."""
            
            else:
                enhanced_content = f"""* 📝 {section_type}
{content}

* 🔍 CONTEXT
- Page: {page_title}
- URL: {current_url}
- Iteration: {iterations + 1}
- Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"""
            
            return enhanced_content
            
        except Exception as e:
            logger.warning(f"Error generating enhanced section: {str(e)}", color='yellow')
            # Fallback to basic format
            return f"* {section_type}\n{content}"

    def _generate_enhanced_ai_process(self, thinking_response, decision_response, page_data, url):
        """Generate enhanced AI thinking process with more context and analysis."""
        try:
            # Extract meaningful information from page data
            # page_data is a string, not a dict, so we need to parse it differently
            page_title = "Unknown Page"
            if page_data and isinstance(page_data, str):
                # Try to extract page title from the page_data string
                if "Page information:" in page_data:
                    # Extract the first line after "Page information:"
                    lines = page_data.split('\n')
                    for line in lines:
                        if line.strip() and not line.startswith("Page information:") and not line.startswith("***"):
                            page_title = line.strip()[:50] + "..." if len(line.strip()) > 50 else line.strip()
                            break
            
            page_url = url
            
            # Generate enhanced AI thinking process
            enhanced_process = f"""* 🧠 THINKING PHASE
{thinking_response}

* 🎯 DECISION PHASE
{decision_response}

* 🔍 CONTEXTUAL ANALYSIS
Based on my analysis of the target:
- Page Title: {page_title}
- Target URL: {page_url}
- Analysis Time: {time.strftime('%Y-%m-%d %H:%M:%S')}

* 🚀 STRATEGIC PLANNING
I am now planning my attack strategy:
1. Understanding the target's security posture
2. Identifying potential attack vectors
3. Choosing the most effective testing approach
4. Preparing to execute targeted security tests

* ⚔️ READY FOR EXECUTION
I have completed my analysis and am ready to begin the security testing phase."""
            
            return enhanced_process
            
        except Exception as e:
            logger.warning(f"Error generating enhanced AI process: {str(e)}", color='yellow')
            # Fallback to basic format
            return f"* THINKING\n{thinking_response}\n\n* DECISION\n{decision_response}"

    def _generate_intelligent_ai_response(self, thinking_response, decision_response, page, url, iterations):
        """Generate intelligent and contextual AI response based on actual analysis."""
        try:
            # Get current page context
            page_title = page.title if hasattr(page, 'title') else "Unknown Page"
            current_url = page.url
            
            # Analyze the current situation
            context_analysis = f"""* THINKING ANALYSIS
Based on my previous analysis: {thinking_response}

* CURRENT SITUATION
- Page: {page_title}
- URL: {current_url}
- Iteration: {iterations + 1}
- Previous Decision: {decision_response}

* SECURITY ASSESSMENT
I need to evaluate the current page for potential vulnerabilities. Let me analyze:
1. What elements are present on this page?
2. What security risks could exist?
3. What testing approach would be most effective?
4. Should I use external tools or internal tools?

* STRATEGIC DECISION
Based on my analysis, I will:
- First assess the page structure and identify attack vectors
- Choose the most appropriate testing method
- Execute targeted security tests
- Analyze the results for vulnerabilities

* ACTION PLAN
I will now implement my security testing strategy using the most effective tools available."""
            
            return context_analysis
            
        except Exception as e:
            logger.warning(f"Error generating intelligent AI response: {str(e)}", color='yellow')
            # Fallback to basic response
            return f"""* DISCUSSION
The page analysis identified forms that could be vulnerable to Injection attacks. I will attempt an SQL injection by filling a form field with a malicious payload and submitting it in the next step.

* ACTION
fill(page, "input", "'; DROP TABLE users; --")"""

    def _load_attack_state(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM attack_state ORDER BY timestamp DESC LIMIT 1")
        row = cursor.fetchone()
        if row:
            state = {
                'url': row[1],
                'plan': {'title': row[2], 'description': row[3]},
                'history': json.loads(row[4]),
                'iterations': row[5],
                'total_plans': row[6],
                'plan_index': row[7],
                'ai_process': row[8]
            }
            cursor.execute("DELETE FROM attack_state")
            conn.commit()
            conn.close()
            return state
        conn.close()
        return None
        
    def _clear_attack_state(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM attack_state")
        conn.commit()
        conn.close()
        
    def load_tool_results(self, url):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT llm_response, tool_use, tool_output FROM tool_results WHERE url = ? ORDER BY timestamp DESC LIMIT 3",
            (url,)
        )
        results = cursor.fetchall()
        conn.close()
        return results

    def save_tool_result(self, url, plan_title, llm_response, tool_use, tool_output):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO tool_results (url, plan_title, llm_response, tool_use, tool_output) VALUES (?, ?, ?, ?, ?)",
            (url, plan_title, llm_response, tool_use, tool_output)
        )
        cursor.execute("""
            DELETE FROM tool_results
            WHERE url = ? AND id NOT IN (
                SELECT id FROM tool_results WHERE url = ?
                ORDER BY timestamp DESC LIMIT 3
            )
        """, (url, url))
        conn.commit()
        conn.close()
    
    def _retry_llm_call(self, history, logger, phase: str, url: str = None, plan: dict = None, iterations: int = None, total_plans: int = None, plan_index: int = None, ai_process: str = None, page=None):
        max_retries = 3
        default_retry_delay = 60
        gemini_api_file = "geminiapi.txt"
        env_file = ".env"
        db_file = "attack_results.db"
        wordlist_dir = "lists"

        def init_db():
            try:
                with sqlite3.connect(db_file) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS attack_results (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            url TEXT,
                            plan_title TEXT,
                            llm_response TEXT,
                            tool_use TEXT,
                            tool_output TEXT,
                            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    conn.commit()
            except sqlite3.Error as e:
                logger.error(f"[Agent._retry_llm_call] Failed to initialize database {db_file}: {str(e)}", color='red')

        def save_attack_result(url, plan_title, llm_response, tool_use, tool_output):
            try:
                with sqlite3.connect(db_file) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO attack_results (url, plan_title, llm_response, tool_use, tool_output) VALUES (?, ?, ?, ?, ?)",
                        (url, plan_title, llm_response, tool_use, tool_output)
                    )
                    cursor.execute("""
                        DELETE FROM attack_results
                        WHERE url = ? AND id NOT IN (
                            SELECT id FROM attack_results WHERE url = ?
                            ORDER BY timestamp DESC LIMIT 3
                        )
                    """, (url, url))
                    conn.commit()
                    logger.debug(f"[Agent._retry_llm_call] Saved attack result for {url} to {db_file}")
            except sqlite3.Error as e:
                logger.error(f"[Agent._retry_llm_call] Failed to save attack result to {db_file}: {str(e)}", color='red')

        def load_attack_results(url):
            try:
                with sqlite3.connect(db_file) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT llm_response, tool_use, tool_output FROM attack_results WHERE url = ? ORDER BY timestamp DESC LIMIT 3",
                        (url,)
                    )
                    results = cursor.fetchall()
                    logger.debug(f"[Agent._retry_llm_call] Loaded {len(results)} attack results for {url} from {db_file}")
                    return results
            except sqlite3.Error as e:
                logger.error(f"[Agent._retry_llm_call] Failed to load attack results from {db_file}: {str(e)}", color='red')
                return []

        def read_gemini_keys():
            """Load Gemini API key from environment variable"""
            api_key = os.getenv("GEMINI_API_KEY", "").strip()
            if not api_key:
                logger.error("[Agent._retry_llm_call] GEMINI_API_KEY not found in .env file.", color='red')
                return []
            return [api_key]

        def update_env_file(new_key):
            try:
                with open(env_file, "r") as f:
                    lines = f.readlines()
                new_lines = []
                key_updated = False
                for line in lines:
                    if line.strip().startswith("GEMINI_API_KEY="):
                        new_lines.append(f"GEMINI_API_KEY={new_key}\n")
                        key_updated = True
                    else:
                        new_lines.append(line)
                if not key_updated:
                    new_lines.append(f"GEMINI_API_KEY={new_key}\n")
                with open(env_file, "w") as f:
                    f.writelines(new_lines)
                logger.info(f"[Agent._retry_llm_call] Updated GEMINI_API_KEY in {env_file}.", color='green')
                os.environ["GEMINI_API_KEY"] = new_key
                return True
            except Exception as e:
                logger.error(f"[Agent._retry_llm_call] Failed to update {env_file}: {str(e)}", color='red')
                return False

        def get_wordlists():
            if os.path.exists(wordlist_dir) and os.path.isdir(wordlist_dir):
                return [f for f in os.listdir(wordlist_dir) if f.endswith('.txt')]
            logger.warning(f"[Agent._retry_llm_call] Wordlist directory {wordlist_dir} not found or not a directory.", color='yellow')
            return []

        def load_wordlist(file_name):
            file_path = os.path.join(wordlist_dir, file_name)
            try:
                with open(file_path, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                logger.error(f"[Agent._retry_llm_call] Failed to load wordlist {file_name}: {str(e)}", color='red')
                return []

        def extract_domain(url):
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            domain = parsed_url.hostname or parsed_url.path.split(':')[0]
            return domain if domain else "unknown"

        init_db()
        prev_results = load_attack_results(url) if url and phase == "attack_execution" else []
        if prev_results:
            logger.info(f"[Agent._retry_llm_call] Loaded {len(prev_results)} previous attack results for {url}.", color='green')
            for llm_response, tool_use, tool_output in prev_results:
                history.append({"role": "assistant", "content": llm_response})
                history.append({"role": "user", "content": f"* PREVIOUS ATTACK RESULT\nTool Used: {tool_use}\nOutput: {tool_output}\nAnalyze this to plan the next step, identifying vulnerabilities like SQL injection, file uploads, or buffer overflows."})

        gemini_keys = read_gemini_keys() if self.provider.lower() == "gemini" else []
        current_key_index = -1

        try:
            with open("tools_config.json", "r") as f:
                external_tools = json.load(f)
        except FileNotFoundError:
            external_tools = []
            logger.warning("[Agent._retry_llm_call] tools_config.json not found. Using internal tools only.", color='yellow')

        external_tools_prompt = "\nAvailable External Tools:\n" + (
            "\n".join([
                f"- execute_external_tool(\"{tool['tool_name']}\", {json.dumps({param['name']: param['description'] for param in tool['parameters']})}) - {tool['description']} (Context: {tool['security_context']})"
                for tool in external_tools
            ]) if external_tools else "No external tools available. Use internal tools or custom logic."
        )

        target_domain = extract_domain(self.starting_url)

        if phase == "attack_execution":
            form_detected = any("form" in msg["content"].lower() or "input" in msg["content"].lower() for msg in history)
            has_interactive_elements = False
            if page:
                page_content = page.content()[:1000]
                has_interactive_elements = any(elem in page_content.lower() for elem in ["form", "input", "button", "a href"])

            if page:
                history.append({"role": "user", "content": f"""
                    * PAGE CONTEXT
                    Current page content snippet: {page_content}
                    Target domain/IP: {target_domain}
                    Analyze for vulnerabilities (e.g., parameter-based URLs for SQL injection, file upload forms, or custom binaries for buffer overflows). If a login form is detected, attempt brute-forcing or navigation.
                """})

            wordlists = get_wordlists()
            if wordlists:
                history.append({"role": "user", "content": f"""
                    * WORDLIST SUGGESTION
                    Wordlists in {wordlist_dir}: {', '.join(wordlists)}. Use these for brute-forcing credentials, directories, or payloads (e.g., 'passwords.txt' for login, 'subdomains.txt' for enumeration) if vulnerabilities like SQL injection or file uploads are suspected.
                """})

            if external_tools:
                history.append({"role": "user", "content": f"""
                    * EXTERNAL TOOLS AVAILABLE (OPTIONAL)
                    {external_tools_prompt}
                    
                    NOTE: External tools are OPTIONAL and should only be used when you determine they would be beneficial for your attack strategy. You can:
                    - Use external tools if you think they would help discover vulnerabilities
                    - Skip external tools and rely on internal tools and manual testing
                    - Make your own decision based on the current situation
                    
                    Do NOT feel obligated to use external tools. Focus on what makes sense for your current attack strategy.
                """})

            history.append({"role": "user", "content": f"""
                * ATTACK STRATEGY
                You are a creative penetration tester targeting OWASP Top 10 vulnerabilities. Analyze page content, previous results, and available tools to devise attacks:
                - **SQL Injection:** Test parameters (e.g., 'id=1') with single quotes or other injection payloads
                - **File Upload:** Upload a PHP shell if a form allows it, then locate and execute it
                - **Buffer Overflow:** Identify custom binaries and craft payloads to redirect execution (e.g., to a secret function)
                - **Login Brute-Forcing:** Use wordlists or manual testing on login forms
                
                You can choose to use external tools if you think they would help, or rely on internal tools and manual testing. Make your own strategic decisions.
                After any action (e.g., form submission), evaluate the response for success or further clues. Always press a submit button if a form is present.
            """})

            if not any("fill" in msg["content"].lower() or "submit" in msg["content"].lower() or "execute_external_tool" in msg["content"].lower() for msg in history[-5:]):
                history.append({"role": "user", "content": f"""
                    * MANDATORY ACTION
                    No recent action detected. If a form is present, fill it and press the submit button. Otherwise, navigate to common paths (e.g., /administrator) or use manual testing to discover vulnerabilities.
                    
                    You can choose to use external tools if you think they would help, but this is not required. Focus on what makes sense for your current situation.
                """})

        response = None
        for attempt in range(max_retries):
            try:
                response = self.llm.reason(history)
                if phase == "attack_execution" and response and page:
                    response = self._reformat_anthropic_response(response, task_context="\n".join([msg["content"] for msg in history]), page=page)

                if phase == "attack_execution" and url and plan and response:
                    tool_use = self.tools.extract_tool_use(response)
                    if tool_use:
                        tool_output = str(self.tools.execute_tool(page, tool_use))
                        save_attack_result(url, plan.get('title', 'Unknown Plan'), response, tool_use, tool_output)
                        history.append({"role": "user", "content": f"* TOOL OUTPUT\n{tool_output}\nEvaluate the response for exploitation opportunities (e.g., SQL errors, uploaded file paths, or shell access)."})
                break
            except Exception as e:
                if ("google.api_core.exceptions.ResourceExhausted" in str(type(e)) or
                    "quota" in str(e).lower() or
                    "rate limit" in str(e).lower() or
                    ("google.api_core.exceptions.InvalidArgument" in str(type(e)) and "API key not valid" in str(e).lower())):
                    retry_delay_match = re.search(r'retry_delay\s*\{\s*seconds:\s*(\d+)\s*\}', str(e))
                    retry_delay = int(retry_delay_match.group(1)) if retry_delay_match else default_retry_delay
                    error_type = "Invalid API key" if "InvalidArgument" in str(type(e)) else "Quota limit"
                    logger.info(f"{error_type} detected during {phase} phase (attempt {attempt + 1}/{max_retries}). Waiting {retry_delay} seconds before retrying...")
                    time.sleep(retry_delay)
                else:
                    logger.error(f"Error during {phase} phase: {str(e)}")
                    break

        if response is None:
            logger.error(f"Max retries exceeded for {phase} phase. Returning None.")
            return None

        return response
    
    
    def run(self, logger):
        self._clear_error_logs()
        self._clear_attack_state()
        print_hacker_header("INITIALIZING HACKNET SYSTEM", logger, color='green')
        
        logger.debug("[Agent.run] Starting run method")
        logger.debug(f"[Agent.run] Tools instance has logger: {hasattr(self.tools, 'logger')}")
        browser, context, page, playwright = self.proxy.create_proxy()
        urls_to_parse = [self.starting_url]

        # Load external tools configuration
        try:
            with open("tools_config.json", "r") as f:
                external_tools = json.load(f)
        except FileNotFoundError:
            external_tools = []
            logger.warning("[Agent.run] tools_config.json not found. Proceeding with internal tools only.", color='yellow')
        
        external_tools_prompt = "\nAvailable External Tools:\n" + (
            "\n".join([
                f"- execute_external_tool(\"{tool['tool_name']}\", {json.dumps({param['name']: param['description'] for param in tool['parameters']})}) - {tool['description']} (Context: {tool['security_context']})"
                for tool in external_tools
            ]) if external_tools else "No external tools available. Use internal tools or custom logic."
        )

        try:
            if self.should_enumerate_subdomains:
                logger.info("[+] ENUMERATING SUBDOMAINS - STAND BY")
                subdomains = enumerate_subdomains(self.starting_url)
                subdomains = [sub for sub in subdomains if urlparse(sub).netloc.endswith(self.starting_domain)]
                urls_to_parse.extend(subdomains)
            
            self.reports = []
            logger.info("[+] INITIALIZING SCANNER")
            self.scanner = PageAnalyzer(page)

            total_tokens = 0
            resume_state = self._load_attack_state()
            ignored_urls = set()

            total_urls = len(urls_to_parse)
            progress_bar = tqdm(
                total=total_urls,
                desc="Scanning URLs",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [HACKING] {desc}",
                ncols=80,
                dynamic_ncols=True
            )

            # Define some neutral but interesting dynamic messages
            dynamic_messages = [
                "// ANALYZING NETWORK...",
                "// PROBING SYSTEMS...",
                "// MAPPING RESOURCES...",
                "// TRACKING DATA FLOW..."
            ]
            while urls_to_parse:
                url = urls_to_parse.pop(0)
                target_ip, target_port = get_target_ip_and_port(url)

                print_hacker_header(f"STARTING SCAN: {url}", logger, color='cyan')
                try:
                    start_time = time.time()
                    timeout = 30  # 30 seconds timeout
                    while time.time() - start_time < timeout:
                        scan_results = self.scanner.scan(url, self.tools)
                        if scan_results:  # Check if scan succeeded
                            break
                        time.sleep(1)  # Small delay before retrying
                    else:
                        raise TimeoutError(f"Scan timed out after {timeout} seconds for {url}")
                except TimeoutError as e:
                    logger.error(f"Scan timed out for {url}: {str(e)}")
                    progress_bar.update(1)
                    continue
                except Exception as e:
                    logger.error(f"Failed to scan {url}: {str(e)}")
                    progress_bar.update(1)
                    continue

                # Randomly insert dynamic messages
                if random.random() < 0.3:  # 30% chance to show dynamic message
                    current_message = random.choice(dynamic_messages)
                    progress_bar.set_description(f"Scanning URLs {current_message}")

                if self.expand_scope:
                    more_urls = scan_results["parsed_data"]["urls"]
                    new_urls = 0
                    skip_keywords = ["logout", "log out", "sign_out", "sign out", "logout", "sign in", "login", "register", "signup", "forgot password", "reset password"]

                    for _url in more_urls:
                        href = _url.get("href", "")
                        text = _url.get("text", "")
                        href_domain = urlparse(href).netloc
                        if not href_domain.endswith(self.starting_domain):
                            if href not in ignored_urls:
                                logger.info(f"Ignoring external URL: {href} (outside domain {self.starting_domain})", color='yellow')
                                ignored_urls.add(href)
                            continue
                        if any(kw in href.lower() for kw in skip_keywords) or any(kw in text.lower() for kw in skip_keywords):
                            continue
                        if href not in urls_to_parse and check_hostname(self.starting_url, href):
                            urls_to_parse.append(href)
                            new_urls += 1
                            total_urls += 1
                            progress_bar.total = total_urls

                    if new_urls > 0:
                        print_hacker_terminal("URL EXPANSION", f"Added {new_urls} new URLs to the search queue", logger, color='green')

                page_source = scan_results["html_content"]
                total_tokens += count_tokens(page_source)
                
                # AI Chatbot Detection and Testing
                if self.ai_chatbot_detector:
                    try:
                        print_hacker_terminal("AI_DETECTION", "Scanning for AI Chatbots...", logger, color='cyan')
                        
                        # Get network traffic from proxy if available
                        network_traffic = []
                        if hasattr(self.proxy, 'get_captured_requests'):
                            network_traffic = self.proxy.get_captured_requests()
                        
                        # Detect AI Chatbots
                        detected_chatbots = self.ai_chatbot_detector.detect_in_page(
                            page_source, 
                            network_traffic=network_traffic,
                            current_url=url
                        )
                        
                        if detected_chatbots:
                            logger.info(f"[AI_DETECTION] Found {len(detected_chatbots)} AI Chatbot(s)", color='yellow')
                            
                            for chatbot in detected_chatbots:
                                chatbot_type = self.ai_chatbot_detector.identify_chatbot_type(chatbot)
                                logger.info(f"[AI_DETECTION] Chatbot Type: {chatbot_type}", color='yellow')
                                logger.info(f"[AI_DETECTION] Confidence: {chatbot.get('confidence', 0):.2f}", color='yellow')
                                
                                # Identify provider
                                provider = 'unknown'
                                if self.ai_service_fingerprinter:
                                    provider = self.ai_service_fingerprinter.identify_provider(
                                        url=chatbot.get('endpoints', [url])[0] if chatbot.get('endpoints') else url
                                    ) or 'unknown'
                                
                                # Test for Prompt Injection vulnerabilities
                                if self.prompt_injection_tester and chatbot.get('endpoints'):
                                    print_hacker_terminal("AI_TESTING", f"Testing {chatbot_type} for vulnerabilities...", logger, color='red')
                                    
                                    for endpoint in chatbot.get('endpoints', []):
                                        if endpoint:
                                            logger.info(f"[AI_TESTING] Testing endpoint: {endpoint}", color='cyan')
                                            
                                            # Run Prompt Injection tests
                                            test_results = self.prompt_injection_tester.test_chatbot(
                                                endpoint,
                                                chatbot_type=chatbot_type,
                                                provider=provider
                                            )
                                            
                                            # Analyze and classify vulnerabilities
                                            if test_results:
                                                vulnerable_tests = [r for r in test_results if r.get('vulnerable', False)]
                                                
                                                if vulnerable_tests:
                                                    logger.warning(f"[AI_TESTING] Found {len(vulnerable_tests)} vulnerabilities!", color='red')
                                                    
                                                    for vuln in vulnerable_tests:
                                                        # Classify vulnerability
                                                        if self.ai_vulnerability_classifier:
                                                            classified = self.ai_vulnerability_classifier.classify_vulnerability(vuln)
                                                            logger.warning(
                                                                f"[AI_VULN] {classified['type']}/{classified['subtype']}: "
                                                                f"{classified['severity']} - {classified['description']}",
                                                                color='red'
                                                            )
                                                            
                                                            # Save to report
                                                            self.reporter.add_vulnerability(
                                                                url=endpoint,
                                                                vulnerability_type=f"AI_{classified['type']}",
                                                                description=classified['description'],
                                                                severity=classified['severity'],
                                                                evidence=classified.get('evidence', ''),
                                                                payload=classified.get('payload', '')
                                                            )
                                
                                # Test RAG system if detected
                                if self.ai_chatbot_detector.is_rag_system(chatbot) and self.rag_system_tester:
                                    logger.info("[AI_TESTING] RAG system detected, testing for poisoning...", color='cyan')
                                    
                                    for endpoint in chatbot.get('endpoints', []):
                                        if endpoint:
                                            rag_results = self.rag_system_tester.test_vector_db_poisoning(endpoint, url)
                                            
                                            vulnerable_rag = [r for r in rag_results if r.get('vulnerable', False)]
                                            if vulnerable_rag:
                                                logger.warning(f"[AI_TESTING] RAG poisoning vulnerability found!", color='red')
                                                for vuln in vulnerable_rag:
                                                    self.reporter.add_vulnerability(
                                                        url=endpoint,
                                                        vulnerability_type="AI_RAG_Poisoning",
                                                        description="Vector database poisoning vulnerability",
                                                        severity="high",
                                                        evidence=vuln.get('evidence', ''),
                                                        payload=vuln.get('payload', '')
                                                    )
                        else:
                            logger.info("[AI_DETECTION] No AI Chatbots detected", color='dim')
                    except Exception as e:
                        logger.error(f"[AI_DETECTION] Error during AI Chatbot detection: {str(e)}", color='red')
                
                summarizer = Summarizer(model_provider=self.provider, model_name=self.model)
                try:
                    page_source = summarizer.summarize_page_source(page_source, url)
                except Exception as e:
                    logger.error(f"Failed to summarize page source for {url}: {str(e)}. Using raw content.", color='red')
                    page_source = page_source[:1000] + "..."  # Truncate if summarization fails
                page_data = f"Page information: {page_source}\n*** URL of the page we are planning for: {url} ***"

                self.history = [
                    {"role": "system", "content": self.llm.system_prompt},
                    {"role": "user", "content": page_data}
                ]

                # Enhanced hacker-style AI thinking output
                print_hacker_double_box("🧠 AI THINKING: ANALYZING PAGE", logger, color='light_cyan')
                
                # Add dynamic thinking indicators
                thinking_indicators = [
                    "🔍 Scanning page structure for attack vectors...",
                    "💻 Analyzing HTML for injection points...",
                    "🔐 Checking authentication mechanisms...",
                    "🌐 Identifying exposed endpoints...",
                    "⚡ Mapping potential vulnerabilities...",
                    "🎯 Planning attack strategy...",
                    "🚨 Assessing security posture...",
                    "💡 Evaluating exploit possibilities..."
                ]
                
                for indicator in random.sample(thinking_indicators, 3):
                    print_hacker_terminal("AI_PROCESSING", indicator, logger, color='dim cyan')
                    time.sleep(0.5)  # Brief pause for dramatic effect
                
                thinking_prompt = f"""
            Analyze the following page data and identify potential vulnerabilities or entry points for security testing, focusing on ALL OWASP Top 10 vulnerabilities:
            1. Injection (e.g., SQL injection, command injection)
            2. Broken Authentication (e.g., weak login mechanisms)
            3. Sensitive Data Exposure (e.g., exposed API keys, unencrypted data)
            4. XML External Entities (XXE) (e.g., XML input processing)
            5. Broken Access Control (e.g., accessing unauthorized endpoints)
            6. Security Misconfiguration (e.g., default configurations, exposed admin panels)
            7. Cross-Site Scripting (XSS) (e.g., script injection in inputs)
            8. Insecure Deserialization (e.g., unsafe deserialization of user input)
            9. Using Components with Known Vulnerabilities (e.g., outdated libraries)
            10. Insufficient Logging & Monitoring (e.g., lack of logging for security events)

            IMPORTANT: Focus primarily on your own analysis and internal tools. External tools should only be used when absolutely necessary and when you cannot achieve the same result with internal tools.

            {external_tools_prompt}

            STRATEGY: Start with manual analysis and internal tools. Only use external tools when:
            1. You need network-level information that internal tools cannot provide
            2. You need specialized vulnerability scanning that internal tools cannot perform
            3. You have exhausted all internal tool options and need additional reconnaissance

            {page_data}

            Provide your analysis in the following format:

            * THINKING
            [Your detailed analysis of the page, identifying potential vulnerabilities from the OWASP Top 10 list above. Focus on manual analysis first, then consider if external tools are truly necessary. For each vulnerability, explain your reasoning and preferred approach.]
            """
                self.history.append({"role": "user", "content": thinking_prompt})
                thinking_response = self._retry_llm_call(
                    history=self.history,
                    logger=logger,
                    phase="thinking",
                    page=page
                )
                if thinking_response is None:
                    logger.error("Failed to complete thinking phase after quota retries. Skipping URL.", color='red')
                    progress_bar.update(1)
                    continue
                self.history.append({"role": "assistant", "content": thinking_response})
                
                # Check if AI mentioned external tools and execute them
                if self.ai_tool_detector:
                    tool_results = self.ai_tool_detector.execute_detected_tools(thinking_response)
                    if tool_results:
                        tool_output = self.ai_tool_detector.format_tool_results_for_ai(tool_results)
                        logger.info(f"[Agent] External tools executed: {len(tool_results)} tools", color='green')
                        
                        # Add tool results to history
                        self.history.append({"role": "user", "content": f"* EXTERNAL TOOL EXECUTION RESULTS\n{tool_output}"})
                        
                        # Update thinking response with tool results
                        thinking_response += f"\n\n* EXTERNAL TOOL RESULTS\n{tool_results}"
                
                # Enhanced hacker-style AI decision output
                print_hacker_double_box("🎯 AI DECISION: GENERATING ATTACK PLAN", logger, color='light_cyan')
                
                # Add dynamic decision indicators
                decision_indicators = [
                    "⚔️ Crafting attack strategy...",
                    "🎯 Selecting optimal tools...",
                    "🚀 Planning attack sequence...",
                    "💣 Preparing payloads...",
                    "🔒 Analyzing target defenses...",
                    "⚡ Optimizing attack vectors...",
                    "🎭 Setting up attack scenarios...",
                    "🚨 Finalizing exploit plans..."
                ]
                
                for indicator in random.sample(decision_indicators, 3):
                    print_hacker_terminal("AI_STRATEGY", indicator, logger, color='dim yellow')
                    time.sleep(0.5)  # Brief pause for dramatic effect
                
                decision_prompt = f"""
        Based on your analysis of the page:

        {thinking_response}

        {external_tools_prompt}

        Generate a security testing plan to target the identified vulnerabilities, focusing on ALL OWASP Top 10 vulnerabilities:
        1. Injection (e.g., SQL injection, command injection)
        2. Broken Authentication (e.g., weak login mechanisms)
        3. Sensitive Data Exposure (e.g., exposed API keys, unencrypted data)
        4. XML External Entities (XXE) (e.g., XML input processing)
        5. Broken Access Control (e.g., accessing unauthorized endpoints)
        6. Security Misconfiguration (e.g., default configurations, exposed admin panels)
        7. Cross-Site Scripting (XSS) (e.g., script injection in inputs)
        8. Insecure Deserialization (e.g., unsafe deserialization of user input)
        9. Using Components with Known Vulnerabilities (e.g., outdated libraries)
        10. Insufficient Logging & Monitoring (e.g., lack of logging for security events)

        Incorporate any previous tool outputs (including external tools like nmap or sqlmap) to refine your strategy. For example, if an external tool revealed open ports or potential injection points, prioritize those in your plan.

        Provide your decision in the following format:

        * DECISION
        [Your decision on the attack strategy, specifying which OWASP Top 10 vulnerabilities to target and the general approach you will take. You can choose to use external tools if you think they would help, or rely on internal tools and manual testing. Make your own strategic decision based on what makes sense for the current situation. Do not include specific payloads or commands here; focus on the strategy.]
        """
                self.history.append({"role": "user", "content": decision_prompt})
                decision_response = self._retry_llm_call(
                    history=self.history,
                    logger=logger,
                    phase="decision",
                    page=page
                )
                if decision_response is None:
                    logger.error("Failed to complete decision phase after quota retries. Skipping URL.", color='red')
                    progress_bar.update(1)
                    continue
                self.history.append({"role": "assistant", "content": decision_response})

                # Generate more intelligent and contextual AI thinking process
                ai_process = self._generate_enhanced_ai_process(thinking_response, decision_response, page_data, url)
                wrapped_ai_process = wrap_text_preserve_words(ai_process, width=120)
                print_hacker_output("PAGE ANALYSIS", "No findings yet.", logger, color='cyan', target_ip=target_ip, target_port=target_port, ai_process=wrapped_ai_process, llm=self.llm, hide_ip=self.hide_ip)
                print_hacker_terminal("ATTACK STRATEGY", decision_response, logger, color='yellow')

                plans = self.planner.plan(page_data)
                total_plans = len(plans)
                for index, plan in enumerate(plans):
                    print_hacker_terminal(f"PLAN {index + 1}/{total_plans}", f"Title: {plan['title']}\nDescription: {plan.get('description', 'No detailed description available')}", logger, color='light_magenta')

                # Hacker-style dynamic progress during attack execution
                attacker_ip = get_attacker_ip()
                # target_ip/port already resolved above for this URL
                progress = _create_hacker_progress(attacker_ip, target_ip, target_port)
                with progress:
                    # Set start_index based on resume_state
                    start_index = resume_state['plan_index'] if resume_state else 0
                    task_plans = progress.add_task("[magenta]ATTACK PLANS[/magenta]", total=total_plans)
                    if start_index:
                        progress.update(task_plans, completed=start_index, description=f"Resuming at plan {start_index+1}/{total_plans}")

                    for index, plan in enumerate(plans[start_index:], start=start_index):
                        if resume_state:
                            self.history = resume_state['history']
                            iterations = resume_state['iterations']
                            total_plans = resume_state['total_plans']
                            ai_process = resume_state['ai_process']
                            resume_state = None
                        else:
                            self.history = self.history[:2]
                            iterations = 0
                            # Generate more intelligent and contextual AI thinking process
                            ai_process = self._generate_enhanced_ai_process(thinking_response, decision_response, page_data, url)

                        # Enhanced hacker-style plan execution output
                        print_hacker_double_box(f"⚔️ EXECUTING PLAN {index + 1}/{total_plans}: {plan['title']}", logger, color='light_cyan')
                        
                        # Add dynamic execution indicators
                        execution_indicators = [
                            "🚀 Initializing attack sequence...",
                            "💻 Loading attack tools...",
                            "🎯 Targeting vulnerabilities...",
                            "⚡ Executing payloads...",
                            "🔍 Monitoring responses...",
                            "💣 Deploying exploits...",
                            "🚨 Analyzing results...",
                            "⚔️ Adapting strategy..."
                        ]
                        
                        for indicator in random.sample(execution_indicators, 2):
                            print_hacker_terminal("ATTACK_EXECUTION", indicator, logger, color='dim red')
                            time.sleep(0.3)  # Brief pause for dramatic effect

                        form_filled = False
                        last_action = None

                        # Per-plan iteration task
                        task_iter = progress.add_task(f"[cyan]{plan['title']}[/cyan]", total=self.max_iterations)
                        progress.update(task_iter, description=_hacker_status(0, self.max_iterations, tool="INIT"))

                        tool_context = f"""
                    You are a security testing agent with specific tools at your disposal. You MUST use these tools to actively test the website for security vulnerabilities, focusing on ALL OWASP Top 10 vulnerabilities:
                    1. Injection (e.g., SQL injection, command injection)
                    2. Broken Authentication (e.g., weak login mechanisms)
                    3. Sensitive Data Exposure (e.g., exposed API keys, unencrypted data)
                    4. XML External Entities (XXE) (e.g., XML input processing)
                    5. Broken Access Control (e.g., accessing unauthorized endpoints)
                    6. Security Misconfiguration (e.g., default configurations, exposed admin panels)
                    7. Cross-Site Scripting (XSS) (e.g., script injection in inputs)
                    8. Insecure Deserialization (e.g., unsafe deserialization of user input)
                    9. Using Components with Known Vulnerabilities (e.g., outdated libraries)
                    10. Insufficient Logging & Monitoring (e.g., lack of logging for security events)

                    Available Tools:
                    Internal Tools:
                    - goto(page, "URL") - Navigate to a URL
                    - click(page, "selector") - Click an element
                    - fill(page, "selector", "value") - Fill a form field
                    - submit(page, "selector") - Submit a form
                    - execute_js(page, "js_code") - Execute JavaScript code
                    - auth_needed() - Signal authentication is needed
                    - refresh(page) - Refresh the page
                    - complete() - Mark test as complete
                    - python_interpreter("code") - Execute Python code
                    - get_user_input("prompt") - Request user input
                    - presskey(page, "key") - Simulate key press
                    {external_tools_prompt}

                    Guidance:
                    - You can choose to use external tools if you think they would help, or rely on internal tools and manual testing
                    - Match tools to vulnerabilities based on your own analysis
                    - If no interactive elements are detected, you can choose to use external tools OR manual testing approaches
                    - Make your own strategic decisions about what tools to use
                    ALWAYS format your response using EXACTLY this structure:
                    * DISCUSSION
                    [Your analysis of the security situation and testing strategy. Specify which OWASP Top 10 vulnerability you're targeting and how you plan to test it. Suggest an appropriate tool based on the context and previous outputs.]
                    * ACTION
                    [Exactly ONE tool command with proper syntax and all required parameters. For external tools, use: execute_external_tool("tool_name", {{"parameters"}}).]
                    """
                        self.history.append({"role": "user", "content": tool_context})

                        plan_instruction = f"""
        I need you to execute the following security test plan, focusing on ALL OWASP Top 10 vulnerabilities:
        1. Injection (e.g., SQL injection, command injection)
        2. Broken Authentication (e.g., weak login mechanisms)
        3. Sensitive Data Exposure (e.g., exposed API keys, unencrypted data)
        4. XML External Entities (XXE) (e.g., XML input processing)
        5. Broken Access Control (e.g., accessing unauthorized endpoints)
        6. Security Misconfiguration (e.g., default configurations, exposed admin panels)
        7. Cross-Site Scripting (XSS) (e.g., script injection in inputs)
        8. Insecure Deserialization (e.g., unsafe deserialization of user input)
        9. Using Components with Known Vulnerabilities (e.g., outdated libraries)
        10. Insufficient Logging & Monitoring (e.g., lack of logging for security events)

        PLAN: {plan['title']}
        DETAILS: {plan['description']}

        Previous Analysis:
        * THINKING: {thinking_response}
        * DECISION: {decision_response}

        {external_tools_prompt}

        Please implement this plan step by step using the tools available to you. For your first action, examine the page content and determine the most appropriate tool to use (either internal or external). If a form is identified in the THINKING or DECISION phase, prioritize testing for Injection (e.g., SQL injection with payload "'; DROP TABLE users; --") or XSS (e.g., "<script>alert('xss')</script>") by filling the form with a malicious payload and submitting it. If an external tool is relevant (e.g., nmap for network scanning, sqlmap for SQL injection), consider using it based on the context and previous tool outputs, but you may choose internal tools if they are more appropriate. Always include a tool command in your ACTION section. If testing form-based attacks (e.g., Injection, XSS), ensure you simulate human submission by following fill() with submit() or presskey(page, "Enter") in the next step. If an external tool fails, fall back to internal tools or custom logic.
        """
                        self.history.append({"role": "user", "content": plan_instruction})

                        while iterations < self.max_iterations:
                            if len(self.history) > self.keep_messages:
                                keep_from_end = self.keep_messages - 4
                                summarizer = Summarizer(model_provider=self.provider, model_name=self.model)
                                self.history = self.history[:4] + summarizer.summarize_conversation(self.history[4:-keep_from_end]) + self.history[-keep_from_end:]

                            plan_tokens = count_tokens(self.history)
                            total_tokens += plan_tokens
                            logger.debug(f"Total tokens used till now: {total_tokens:,}, current query tokens: {plan_tokens:,}")

                            if form_filled and last_action and "fill(page," in last_action:
                                match = re.search(r'fill\(page,\s*"([^"]+)"', last_action)
                                form_selector = match.group(1).split('#')[0] if match else "form"
                                try:
                                    # Only submit if the selector exists
                                    if page.query_selector(form_selector):
                                        llm_response = f"""
* DISCUSSION
The previous step filled a form field with a malicious payload to test for Injection vulnerabilities. Now, I will submit the form to trigger the potential vulnerability and observe the server's response.

* ACTION
submit(page, "{form_selector}")
"""
                                    else:
                                        logger.warning(f"No element found with selector: {form_selector}. Skipping submission.", color='yellow')
                                        llm_response = f"""
* DISCUSSION
Tried to submit a form after filling, but no form element was found on the page. Skipping submission and continuing with other actions.
"""
                                except Exception as e:
                                    logger.error(f"Error checking form selector: {form_selector}: {e}", color='red')
                                    llm_response = f"""
* DISCUSSION
Error occurred when checking for form element: {e}. Skipping submission.
"""
                                form_filled = False
                            else:
                                llm_response = self._retry_llm_call(
                                    history=self.history,
                                    logger=logger,
                                    phase="attack_execution",
                                    url=url,
                                    plan=plan,
                                    iterations=iterations,
                                    total_plans=total_plans,
                                    plan_index=index,
                                    ai_process=ai_process,
                                    page=page
                                )
                                if llm_response is None:
                                    resume_state = self._load_attack_state()
                                    if resume_state:
                                        url = resume_state['url']
                                        target_ip, target_port = get_target_ip_and_port(url)
                                        plans = self.planner.plan(page_data)
                                        break
                                    else:
                                        logger.error("Failed to load attack state after quota wait. Skipping plan.", color='red')
                                        break

                            quota_keywords = ["quota", "Quota", "rate limit", "rate_limit"]
                            additional_context = ["exceeded", "limit", "error", "reached"]
                            if isinstance(llm_response, str) and any(keyword.lower() in llm_response.lower() for keyword in quota_keywords) and any(ctx.lower() in llm_response.lower() for ctx in additional_context):
                                logger.warning("Skipping attack execution step due to detected quota limits in LLM response.", color='yellow')
                                break

                            self.history.append({"role": "assistant", "content": llm_response})
                            fixed_llm_response = llm_response.replace(".  *", ".  \r\n*")

                            # Check if AI mentioned external tools and execute them before proceeding
                            if self.ai_tool_detector:
                                tool_results = self.ai_tool_detector.execute_detected_tools(llm_response)
                                if tool_results:
                                    tool_output = self.ai_tool_detector.format_tool_results_for_ai(tool_results)
                                    logger.info(f"[Agent] External tools executed during attack: {len(tool_results)} tools", color='green')
                                    
                                    # Add tool results to history
                                    self.history.append({"role": "user", "content": f"* EXTERNAL TOOL EXECUTION RESULTS\n{tool_output}"})
                                    
                                    # Update llm_response with tool results
                                    llm_response += f"\n\n* EXTERNAL TOOL RESULTS\n{tool_output}"
                                    fixed_llm_response = llm_response.replace(".  *", ".  \r\n*")
                                    
                                    # Display tool execution results
                                    print_hacker_output("EXTERNAL TOOL EXECUTION", tool_output, logger, color='yellow', 
                                                       target_ip=target_ip, target_port=target_port, 
                                                       ai_process=wrapped_ai_process, llm=self.llm, hide_ip=self.hide_ip)

                            tool_use = self.tools.extract_tool_use(fixed_llm_response)
                            if not tool_use or tool_use in ["goto", "refresh", "auth_needed"] and iterations > 0:
                                if "form" in thinking_response.lower() or "form" in decision_response.lower():
                                    # Generate more intelligent and contextual AI thinking
                                    llm_response = self._generate_intelligent_ai_response(
                                        thinking_response, decision_response, page, url, iterations
                                    )
                                form_filled = True

                            last_action = tool_use
                            if "fill(page," in llm_response:
                                form_filled = True

                            def manage_ai_process(current_ai_process, new_section, max_sections=3):
                                sections = current_ai_process.split('\n\n')
                                sections = [s for s in sections if s.strip()]
                                sections.append(new_section)
                                if len(sections) > max_sections:
                                    older_sections = sections[:-max_sections]
                                    summarizer = Summarizer(model_provider=self.provider, model_name=self.model)
                                    summarized_older = summarizer.summarize_page_source('\n\n'.join(older_sections), url)
                                    sections = [f"* SUMMARY OF PREVIOUS LOGS\n{summarized_older}"] + sections[-max_sections:]
                                return '\n\n'.join(sections)

                            # Enhanced AI process update with better context
                            enhanced_section = self._generate_enhanced_section("DISCUSSION & ACTION", fixed_llm_response, page, url, iterations)
                            ai_process = manage_ai_process(ai_process, enhanced_section, max_sections=3)
                            wrapped_ai_process = wrap_text_preserve_words(ai_process, width=120)
                            print_hacker_output("ATTACK EXECUTION", fixed_llm_response, logger, color='red', target_ip=target_ip, target_port=target_port, ai_process=wrapped_ai_process, llm=self.llm, hide_ip=self.hide_ip)

                            tool_use = self.tools.extract_tool_use(fixed_llm_response)
                            if self.debug:
                                logger.info(f"Extracted tool use: {tool_use}", color='yellow')
                            logger.debug(f"{tool_use}")
                            tools_logger = logging.getLogger('tools')
                            original_level = tools_logger.getEffectiveLevel()
                            tools_logger.setLevel(logging.CRITICAL + 1)
                            try:
                                tool_output = str(self.tools.execute_tool(page, tool_use))
                            finally:
                                tools_logger.setLevel(original_level)

                            raw_tool_output = tool_output
                            current_url = page.url
                            def clean_tool_output(output: str) -> str:
                                lines = output.split('\n')
                                seen = set()
                                unique_lines = []
                                for line in lines:
                                    cleaned_line = line.strip()
                                    if cleaned_line and cleaned_line not in seen:
                                        seen.add(cleaned_line)
                                        unique_lines.append(cleaned_line)
                                return " ".join(unique_lines)

                            cleaned_output = clean_tool_output(tool_output)
                            output_response = f"{cleaned_output[:250]}{'...' if len(cleaned_output) > 250 else ''}"
                            if "execute_external_tool" in tool_use:
                                summarizer = Summarizer(model_provider=self.provider, model_name=self.model)
                                tool_output_summarized = summarizer.summarize(fixed_llm_response, tool_use, tool_output)
                                output_response = f"* EXTERNAL TOOL OUTPUT\n{tool_output_summarized}"
                                if "Error: Tool" in tool_output or "not installed" in tool_output or "failed" in tool_output:
                                    output_response += "\n* FALLBACK\nExternal tool failed. Reverting to internal tools or custom logic for the next step."
                            # Enhanced AI process update for response
                            enhanced_response_section = self._generate_enhanced_section("RESPONSE", output_response, page, url, iterations)
                            ai_process = manage_ai_process(ai_process, enhanced_response_section, max_sections=3)
                            wrapped_ai_process = wrap_text_preserve_words(ai_process, width=120)
                            print_hacker_output("RESPONSE", output_response, logger, color='dark_gray', target_ip=target_ip, target_port=target_port, ai_process=wrapped_ai_process, llm=self.llm, hide_ip=self.hide_ip)
                            time.sleep(2)

                            total_tokens += count_tokens(tool_output)

                            summarizer = Summarizer(model_provider=self.provider, model_name=self.model)
                            tool_output_summarized = summarizer.summarize(llm_response, tool_use, tool_output)
                            self.history.append({"role": "user", "content": f"* TOOL OUTPUT\n{tool_output_summarized}"})

                            # Save tool result to DB
                            with sqlite3.connect(self.db_path) as conn:
                                cursor = conn.cursor()
                                cursor.execute(
                                    "INSERT INTO tool_results (url, plan_title, llm_response, tool_use, tool_output) VALUES (?, ?, ?, ?, ?)",
                                    (url, plan['title'], llm_response, tool_use, tool_output)
                                )
                                cursor.execute("""
                                    DELETE FROM tool_results
                                    WHERE url = ? AND id NOT IN (
                                        SELECT id FROM tool_results WHERE url = ?
                                        ORDER BY timestamp DESC LIMIT 3
                                    )
                                """, (url, url))
                                conn.commit()

                            try:
                                page.goto(current_url)
                            except Exception as e:
                                logger.warning(f"Failed to navigate back to {current_url}: {str(e)}. Continuing...")

                            tool_output = raw_tool_output

                            if tool_output == "Completed":
                                total_tokens += count_tokens(self.history[2:])
                                successful_exploit, report = self.reporter.report(self.history[2:])
                                print_hacker_terminal("EXPLOIT REPORT", f"Analysis of the issue the agent has found: {report}", logger, color='green')

                                if successful_exploit:
                                    print_hacker_terminal("PLAN COMPLETION", "Completed, moving onto the next plan!", logger, color='yellow')
                                    break
                                else:
                                    print_hacker_terminal("PLAN UPDATE", "Need to work harder on the exploit.", logger, color='red')
                                    self.history.append({"role": "user", "content": report + "\n. Lets do better, again!"})

                            traffic = self.proxy.pretty_print_traffic()
                            if traffic:
                                # Enhanced AI process update for network traffic
                                enhanced_traffic_section = self._generate_enhanced_section("NETWORK TRAFFIC", traffic, page, url, iterations)
                                ai_process = manage_ai_process(ai_process, enhanced_traffic_section, max_sections=3)
                                wrapped_traffic = wrap_text_preserve_words(traffic, width=120)
                                wrapped_ai_process = wrap_text_preserve_words(ai_process, width=120)
                                print_hacker_output("NETWORK TRAFFIC", wrapped_traffic, logger, color='cyan', target_ip=target_ip, target_port=target_port, ai_process=wrapped_ai_process, llm=self.llm, hide_ip=self.hide_ip)
                                self.history.append({"role": "user", "content": f"* NETWORK TRAFFIC\n{traffic}"})
                                total_tokens += count_tokens(traffic)
                            self.proxy.clear()

                            iterations += 1
                            if iterations >= self.max_iterations:
                                print_hacker_terminal("ITERATION LIMIT", "Max iterations reached, moving onto the next plan!", logger, color='red')
                                break

                        # Mark plan task as done/advance overall
                        progress.update(task_iter, completed=self.max_iterations, description="[green]Plan complete")
                        progress.update(task_plans, advance=1, description=f"Completed {index+1}/{total_plans}")

                progress_bar.update(1)

            progress_bar.close()
            print_hacker_header("GENERATING SUMMARY REPORT", logger, color='yellow')
            self.reporter.generate_summary_report()

        finally:
            logger.info("Cleaning up resources...")
            self.proxy.close()
            
            # Clean up AI components
            if hasattr(self, 'ai_tool_detector') and self.ai_tool_detector:
                self.ai_tool_detector.cleanup()
            if hasattr(self, 'wordlist_manager') and self.wordlist_manager:
                self.wordlist_manager.cleanup()
        
    def _reformat_anthropic_response(self, original_response: str, task_context: str = "", page=None) -> str:
        import re

        # Define external_tools_prompt for use in this method
        try:
            with open("tools_config.json", "r") as f:
                external_tools = json.load(f)
        except Exception:
            external_tools = []
        external_tools_prompt = "\nAvailable External Tools:\n" + (
            "\n".join([
                f"- execute_external_tool(\"{tool['tool_name']}\", {json.dumps({param['name']: param['description'] for param in tool['parameters']})}) - {tool['description']} (Context: {tool['security_context']})"
                for tool in external_tools
            ]) if external_tools else "No external tools available. Use internal tools or custom logic."
        )

        mentions_form = "form" in original_response.lower() or "input" in task_context.lower()
        mentions_injection = "injection" in original_response.lower() or "xss" in task_context.lower()

        command_with_trailing_text = re.search(r'((?:goto|click|fill|submit|execute_js|refresh|presskey|auth_needed|get_user_input|python_interpreter|complete)\s*\([^)]*\))([a-zA-Z].*)', original_response)
        if command_with_trailing_text:
            command = command_with_trailing_text.group(1)
            explanation = command_with_trailing_text.group(2)
            is_docs_related = 'documentation' in explanation.lower() or 'docs' in explanation.lower() or 'api' in explanation.lower()
            if is_docs_related:
                # Let AI dynamically decide the path instead of hardcoding
                return f"""* DISCUSSION
    {explanation.strip()}
    
    I need to examine the API documentation to understand the endpoints, authentication mechanisms, 
    and potential vulnerabilities. Documentation pages often contain valuable information about the API structure.
    I'll explore common documentation paths to find the right location.

    * ACTION
    {command.strip()}"""
            else:
                return f"""* DISCUSSION
    {explanation.strip()}

    * ACTION
    {command.strip()}"""

        if ('documentation' in original_response.lower() or 'docs' in original_response.lower()) and 'goto' in original_response.lower():
            # Let AI dynamically decide the path instead of hardcoding
            return f"""* DISCUSSION
    I need to examine the API documentation to understand the endpoints, authentication mechanisms, 
    and potential vulnerabilities. Documentation pages often contain valuable information about the API structure.
    I'll explore common documentation paths to find the right location.

    * ACTION
    {original_response.strip()}"""

        tool_patterns = [
            r'goto\(page,\s*[\'"]([^\'"]+)[\'"]\)',
            r'click\(page,\s*[\'"]([^\'"]+)[\'"]\)',
            r'fill\(page,\s*[\'"]([^\'"]+)[\'"],\s*[\'"]([^\'"]+)[\'"]\)',
            r'submit\(page,\s*[\'"]([^\'"]+)[\'"]\)',
            r'execute_js\(page,\s*[\'"](.+?)[\'"]\)',
            r'refresh\(page\)',
            r'presskey\(page,\s*[\'"]([^\'"]+)[\'"]\)',
            r'goto\s*\(page,\s*[\'"]?([^\'"]+)[\'"]?\)',
            r'goto\s+([^\s\)]+)',
            r'goto\s+(https?://[^\s\)]+)',
            r'(?:go|navigate)\s+to\s+[\'"]?([^\'"]+)[\'"]?',
            r'auth_needed\(\)',
            r'complete\(\)',
            r'python_interpreter\([\'"](.+?)[\'"]\)',
            r'get_user_input\([\'"]([^\'"]+)[\'"]\)',
            r'click\s*\(\s*[\'"]([^\'"]+)[\'"]\)',
            r'fill\s*\(\s*[\'"]([^\'"]+)[\'"],\s*[\'"]([^\'"]+)[\'"]\)',
            r'submit\s*\(\s*[\'"]([^\'"]+)[\'"]\)',
            r'refresh\s*\(\s*\)',
            r'(?:curl|request)\s+(https?://[^\s"\']+)'
        ]
        
        content_summary = original_response
        if len(content_summary) > 10000:
            content_summary = original_response[:5000] + " ... " + original_response[-5000:]
        
        command = None
        for pattern in tool_patterns:
            match = re.search(pattern, original_response, re.DOTALL)
            if match:
                command = match.group(0)
                if any(cmd in command for cmd in ["goto(", "click(", "fill(", "submit(", "execute_js(", "refresh("]) and "page" not in command:
                    command = command.replace("goto(", "goto(page, ", 1)
                    command = command.replace("click(", "click(page, ", 1)
                    command = command.replace("fill(", "fill(page, ", 1)
                    command = command.replace("submit(", "submit(page, ", 1)
                    command = command.replace("execute_js(", "execute_js(page, ", 1)
                    command = command.replace("refresh(", "refresh(page)", 1)
                break
        
        if command:
            context_lines = []
            is_discussion_section = False
            for line in original_response.split('\n'):
                line = line.strip()
                if re.match(r'\*\s*DISCUSSION', line, re.IGNORECASE):
                    is_discussion_section = True
                    continue
                if re.match(r'\*\s*ACTION', line, re.IGNORECASE):
                    break
                if is_discussion_section and line:
                    context_lines.append(line)
            
            if not context_lines:
                for line in original_response.split('\n'):
                    line = line.strip()
                    if (line and not any(p in line for p in ["goto(", "click(", "fill(", "execute_js", 
                                                        "submit(", "auth_needed", "complete(", 
                                                        "refresh(", "python_interpreter"])):
                        context_lines.append(line)
                        if len(context_lines) >= 3:
                            break
            
            if not context_lines:
                if "/docs/" in command or "documentation" in command.lower():
                    discussion = "I need to examine the API documentation to understand the endpoints, authentication mechanisms, and potential vulnerabilities. I'll explore common documentation paths dynamically."
                else:
                    discussion = "I'll continue testing the application according to our plan. I need to perform a security test action."
            else:
                discussion = " ".join(context_lines)
            
            return f"""* DISCUSSION
    {discussion}

    * ACTION
    {command}"""
        
        if mentions_form and mentions_injection:
            return f"""* DISCUSSION
    The page analysis identified forms that could be vulnerable to Injection attacks. I will attempt an SQL injection by filling a form field with a malicious payload and submitting it in the next step.

    * ACTION
    fill(page, "input", "'; DROP TABLE users; --")
    """

        template_prompt = f"""
    You are a security testing agent that MUST follow this EXACT FORMAT:

    * DISCUSSION
    [2-3 sentences about security testing strategy]

    * ACTION
    [ONE properly formatted command]

    Valid commands MUST FOLLOW THESE PATTERNS EXACTLY:
    - goto(page, "URL") 
    - click(page, "selector")
    - fill(page, "selector", "value")
    - submit(page, "selector") - Submit a form
    - execute_js(page, "js_code") - Execute JavaScript code
    - auth_needed() - Signal authentication is needed
    - refresh(page) - Refresh the page
    - complete() - Mark test as complete
    - python_interpreter("code") - Execute Python code
    - get_user_input("prompt") - Request user input
    - presskey(page, "key") - Simulate key press
    {external_tools_prompt}

    RULES:
    1. ALWAYS include the page parameter as the FIRST parameter for page interactions
    2. NEVER use natural language in the ACTION section
    3. ONLY extract commands, NEVER invent them if none exists
    4. DO NOT include explanations, notes, or any other text
    5. If you cannot find a valid command and the input mentions forms, default to an injection attack:
    fill(page, "input", "'; DROP TABLE users; --")
    """
        
        if self.debug:
            logger.info("Pattern matching failed, using direct template prompt", color='yellow')
        
        reformatted = self.llm.output(template_prompt, temperature=0)
        
        discussion_match = re.search(r'\*\s*DISCUSSION\s*\n(.+?)(\n\s*\*|\Z)', reformatted, re.DOTALL)
        action_match = re.search(r'\*\s*ACTION\s*\n(.+?)(\n\s*\*|\Z)', reformatted, re.DOTALL)
        
        if discussion_match and action_match:
            if self.debug:
                logger.info("Template-based formatting successful", color='green')
            return reformatted
        
        if self.debug:
            logger.info("Template failed, using system prompt approach", color='yellow')
        
        system_prompt = """
    You are a security testing assistant. Your ONLY job is to extract and format a security testing command from text.

    REQUIRED OUTPUT FORMAT - EXACTLY AS SHOWN:

    * DISCUSSION
    [2-3 sentences about security testing findings extracted from input]

    * ACTION
    [EXACTLY ONE properly formatted command]

    VALID COMMANDS MUST FOLLOW THESE PATTERNS:
    - goto(page, "https://example.com")
    - click(page, "a.nav-link")
    - fill(page, "#input-field", "test value")
    - submit(page, "form#login")
    - execute_js(page, "() => {{ return document.cookie }}")
    - auth_needed()
    - refresh(page)
    - complete()

    RULES:
    1. ALWAYS include the page parameter as the FIRST parameter for page interactions
    2. NEVER use natural language in the ACTION section
    3. ONLY extract commands, NEVER invent them if none exists
    4. DO NOT include explanations, notes, or any other text
    5. If you cannot find a valid command and the input mentions forms, default to an injection attack:
    fill(page, "input", "'; DROP TABLE users; --")
    """
        
        user_prompt = f"Reformat this text into the required format: {original_response}"
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        reformatted = self.llm.reason(messages)
        
        if ("* DISCUSSION" not in reformatted or "* ACTION" not in reformatted or
            "don't have" in original_response.lower() or 
            "can't use" in original_response.lower() or
            "cannot use" in original_response.lower() or
            "don't have capabilities" in original_response.lower() or
            "lack the capabilities" in original_response.lower() or
            "not able to" in original_response.lower()):
            if mentions_form:
                return f"""* DISCUSSION
    The page analysis identified forms that could be vulnerable to Injection attacks. I will attempt an SQL injection by filling a form field with a malicious payload and submitting it in the next step.

    * ACTION
    fill(page, "input", "'; DROP TABLE users; --")
    """
            else:
                return f"""* DISCUSSION
    Starting security testing by examining the page structure. I need to identify potential entry points and interactive elements that could be vulnerable to security issues.

    * ACTION
    goto(page, "{self.starting_url}")
    """
        
        return reformatted
    
    def _get_url_hash(self, url: str) -> str:
        return hashlib.md5(url.encode('utf-8')).hexdigest()

    def _get_content_hash(self, content: str) -> str:
        return hashlib.md5(content.encode('utf-8')).hexdigest()
    
    def _is_url_already_attacked(self, url: str, page_content: str = None) -> bool:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        url_hash = self._get_url_hash(url)
        cursor.execute("SELECT url, page_content_hash, attack_count FROM attacked_urls WHERE url_hash = ?", (url_hash,))
        result = cursor.fetchone()
        if result:
            stored_url, stored_content_hash, attack_count = result
            if page_content:
                current_content_hash = self._get_content_hash(page_content)
                if stored_content_hash == current_content_hash:
                    logger.info(f"[SKIP] URL already attacked with same content: {url} (attacked {attack_count} times)")
                    conn.close()
                    return True
                else:
                    logger.info(f"[RETRY] URL content has changed, will re-attack: {url}", color='cyan')
                    conn.close()
                    return False
            else:
                logger.info(f"[SKIP] URL already attacked: {url} (attacked {attack_count} times)", color='yellow')
                conn.close()
                return True
        conn.close()
        return False
        
  
    
    def _mark_url_as_attacked(self, url: str, page_content: str = None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        url_hash = self._get_url_hash(url)
        content_hash = self._get_content_hash(page_content) if page_content else ""
        try:
            cursor.execute("""
                INSERT INTO attacked_urls (url, url_hash, page_content_hash, attack_count)
                VALUES (?, ?, ?, 1)
            """, (url, url_hash, content_hash))
            logger.info(f"[TRACK] Marked URL as attacked: {url}", color='green')
        except sqlite3.IntegrityError:
            cursor.execute("""
                UPDATE attacked_urls 
                SET attack_count = attack_count + 1, 
                    last_attack_timestamp = CURRENT_TIMESTAMP,
                    page_content_hash = ?
                WHERE url_hash = ?
            """, (content_hash, url_hash))
            logger.info(f"[TRACK] Updated attack count for URL: {url}", color='green')
        conn.commit()
        conn.close()
    
    def _clear_attacked_urls(self):
        """Clear all attack history and tool execution data."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Clear all attack-related tables
        tables_to_clear = [
            "attacked_urls",
            "attacks", 
            "attack_state",
            "tool_results",
            "external_tool_executions",
            "error_logs"
        ]
        
        for table in tables_to_clear:
            try:
                cursor.execute(f"DELETE FROM {table}")
                logger.debug(f"[DB] Cleared table: {table}")
            except sqlite3.OperationalError:
                # Table might not exist yet
                logger.debug(f"[DB] Table {table} doesn't exist yet")
        
        conn.commit()
        conn.close()
        logger.info("[TRACK] Cleared all attack history and tool execution data", color='cyan')


    def _get_attacked_urls_stats(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM attacked_urls")
        total_urls = cursor.fetchone()[0]
        cursor.execute("SELECT SUM(attack_count) FROM attacked_urls")
        total_attacks = cursor.fetchone()[0] or 0
        conn.close()
        return {'total_unique_urls': total_urls, 'total_attacks_saved': total_attacks}
    
    def save_external_tool_execution(self, tool_name: str, target_url: str, command: str, 
                                   parameters: dict, execution_result: dict):
        """
        Save external tool execution results to database.
        
        Parameters:
            tool_name: Name of the external tool
            target_url: Target URL being tested
            command: Command that was executed
            parameters: Parameters used for the tool
            execution_result: Result from tool execution
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Convert parameters and result to JSON strings
            import json
            params_json = json.dumps(parameters)
            result_json = json.dumps(execution_result)
            
            cursor.execute("""
                INSERT INTO external_tool_executions 
                (tool_name, target_url, command, parameters, execution_result, success, execution_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                tool_name,
                target_url,
                command,
                params_json,
                result_json,
                execution_result.get('success', False),
                execution_result.get('execution_time', 0.0)
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"[DB] Saved {tool_name} execution results to database", color='green')
            
        except Exception as e:
            logger.error(f"[DB] Failed to save tool execution results: {str(e)}", color='red')
    
    def get_tool_execution_history(self, tool_name: str = None, limit: int = 50):
        """
        Retrieve tool execution history from database.
        
        Parameters:
            tool_name: Optional filter by specific tool
            limit: Maximum number of records to return
            
        Returns:
            List of tool execution records
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if tool_name:
                cursor.execute("""
                    SELECT * FROM external_tool_executions 
                    WHERE tool_name = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (tool_name, limit))
            else:
                cursor.execute("""
                    SELECT * FROM external_tool_executions 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            # Convert to list of dictionaries
            columns = ['id', 'tool_name', 'target_url', 'command', 'parameters', 
                      'execution_result', 'success', 'execution_time', 'timestamp']
            
            results = []
            for row in rows:
                result = dict(zip(columns, row))
                # Parse JSON fields
                try:
                    result['parameters'] = json.loads(result['parameters'])
                    result['execution_result'] = json.loads(result['execution_result'])
                except:
                    pass
                results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"[DB] Failed to retrieve tool execution history: {str(e)}", color='red')
            return []
