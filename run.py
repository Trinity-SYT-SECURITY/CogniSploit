"""
AI Security Testing Framework
Interactive CLI with AI-driven penetration testing modes
"""
import argparse
import os
import sys
import json
import asyncio
import subprocess
from typing import Dict, List, Optional, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress
from utils.logger import Logger

console = Console()


def print_banner():
    """Display the application banner"""
    banner = """
    ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██╗  ██║ █████╗  ██████╗██╗  ██╗███████╗██████╗ 
    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
    ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████║██████║██║     █████╔╝ █████╗  ██████╔╝
    ██║       ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
    ╚██████╗   ██║   ██║     ███████╗██║  ██║██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
     ╚═════╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    """
    console.print(Panel.fit(banner, style="bold blue", title="AI Security Framework"))


def load_available_tools() -> List[Dict]:
    """Load and validate available external tools from config"""
    tools = []
    config_path = os.path.join(os.path.dirname(__file__), 'tools_config.json')
    
    try:
        with open(config_path, 'r') as f:
            tools_config = json.load(f)
        
        for tool in tools_config:
            tool_name = tool.get('tool_name', '')
            # Check if tool is available on system
            tool['available'] = check_tool_availability(tool_name)
            tools.append(tool)
    except Exception as e:
        console.print(f"[yellow]Warning: Could not load tools config: {e}[/yellow]")
    
    return tools


def check_tool_availability(tool_name: str) -> bool:
    """Check if an external tool is available on the system"""
    try:
        # Use 'where' on Windows, 'which' on Unix
        cmd = 'where' if sys.platform == 'win32' else 'which'
        result = subprocess.run(
            [cmd, tool_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def load_available_wordlists() -> List[str]:
    """Load available dictionary files from lists directory"""
    wordlists = []
    lists_dir = os.path.join(os.path.dirname(__file__), 'lists')
    
    if os.path.exists(lists_dir):
        for filename in os.listdir(lists_dir):
            if filename.endswith('.txt'):
                wordlists.append(filename)
    
    return wordlists


def get_config_path() -> str:
    """Get path to configuration file"""
    return os.path.join(os.path.dirname(__file__), '.scan_config.json')


def save_configuration(config: Dict) -> None:
    """Save user configuration to file"""
    try:
        config_path = get_config_path()
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        console.print(f"[dim]Configuration saved to {config_path}[/dim]")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not save configuration: {e}[/yellow]")


def load_configuration() -> Optional[Dict]:
    """Load saved configuration if exists"""
    try:
        config_path = get_config_path()
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
    except Exception as e:
        console.print(f"[yellow]Warning: Could not load configuration: {e}[/yellow]")
    return None


def display_saved_config(config: Dict) -> None:
    """Display saved configuration"""
    console.print("\n[bold cyan]╔═══════════════════════════════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║           SAVED CONFIGURATION FOUND                            ║[/bold cyan]")
    console.print("[bold cyan]╚═══════════════════════════════════════════════════════════════╝[/bold cyan]")
    
    table = Table(show_header=False)
    table.add_column("Setting", style="cyan", width=20)
    table.add_column("Value", style="green")
    
    mode_names = {
        'web': 'Web Penetration Testing',
        'llm': 'LLM/AI Chatbot Testing',
        'combined': 'Combined (Web + LLM)',
    }
    
    table.add_row("Mode", mode_names.get(config.get('mode', 'web'), config.get('mode', 'web')))
    table.add_row("Last Target", config.get('last_target', 'N/A'))
    table.add_row("AI Model", f"{config.get('model', 'gpt-4o')} ({config.get('provider', 'openai')})")
    table.add_row("Max Iterations", str(config.get('max_iterations', 10)))
    table.add_row("Risk Level", config.get('risk_level', 'medium'))
    table.add_row("External Tools", "Enabled" if config.get('use_external_tools', True) else "Disabled")
    table.add_row("Dictionary Files", "Enabled" if config.get('use_wordlists', True) else "Disabled")
    table.add_row("Output", config.get('output_dir', 'scan_output'))
    
    console.print(table)


def display_mode_selection() -> str:
    """Display mode selection menu and return user choice"""
    console.print("\n[bold cyan]╔═══════════════════════════════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║           SELECT TESTING MODE                                  ║[/bold cyan]")
    console.print("[bold cyan]╚═══════════════════════════════════════════════════════════════╝[/bold cyan]")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Option", style="cyan", width=8)
    table.add_column("Mode", style="green", width=20)
    table.add_column("Description", style="white")
    
    table.add_row("1", "Web Penetration", "AI-driven security testing of web applications")
    table.add_row("2", "LLM/AI Chatbot", "AI-vs-AI testing of chatbots and LLM interfaces")
    table.add_row("3", "Combined", "Comprehensive testing (Web + LLM attack vectors)")
    table.add_row("0", "Exit", "Exit the program")
    
    console.print(table)
    
    choice = Prompt.ask(
        "\n[bold yellow]Select mode[/bold yellow]",
        choices=["0", "1", "2", "3"],
        default="1"
    )
    
    mode_map = {
        "1": "web",
        "2": "llm",
        "3": "combined",
        "0": "exit"
    }
    
    return mode_map.get(choice, "web")


def display_model_selection() -> Tuple[str, str]:
    """Display model selection menu and return model and provider"""
    console.print("\n[bold cyan]╔═══════════════════════════════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║           SELECT AI MODEL                                      ║[/bold cyan]")
    console.print("[bold cyan]╚═══════════════════════════════════════════════════════════════╝[/bold cyan]")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Option", style="cyan", width=8)
    table.add_column("Provider", style="green", width=12)
    table.add_column("Model", style="white", width=25)
    table.add_column("Notes", style="dim")
    
    models = [
        ("1", "OpenAI", "gpt-4o", "Recommended for balanced performance"),
        ("2", "OpenAI", "o3-mini", "Fast, cost-effective"),
        ("3", "Anthropic", "claude-3-5-sonnet-20241022", "Strong reasoning"),
        ("4", "Anthropic", "claude-3-7-sonnet-20250219", "Latest with hybrid reasoning"),
        ("5", "Gemini", "gemini-2.5-pro", "High capacity"),
        ("6", "Gemini", "gemini-2.5-flash", "Balanced speed"),
        ("7", "Ollama", "local", "Local model (offline)"),
        ("8", "LiteLLM", "custom", "Custom provider gateway"),
    ]
    
    for opt, provider, model, notes in models:
        table.add_row(opt, provider, model, notes)
    
    console.print(table)
    
    choice = Prompt.ask(
        "\n[bold yellow]Select model[/bold yellow]",
        choices=[str(i) for i in range(1, 9)],
        default="1"
    )
    
    model_data = {
        "1": ("gpt-4o", "openai"),
        "2": ("o3-mini", "openai"),
        "3": ("claude-3-5-sonnet-20241022", "anthropic"),
        "4": ("claude-3-7-sonnet-20250219", "anthropic"),
        "5": ("gemini-2.5-pro", "gemini"),
        "6": ("gemini-2.5-flash", "gemini"),
        "7": ("local", "ollama"),
        "8": ("custom", "litellm"),
    }
    
    return model_data.get(choice, ("gpt-4o", "openai"))


def display_tools_status(tools: List[Dict]) -> None:
    """Display available external tools status"""
    console.print("\n[bold cyan]External Tools Status:[/bold cyan]")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Tool", style="white", width=12)
    table.add_column("Status", style="white", width=12)
    table.add_column("Purpose", style="dim")
    
    for tool in tools:
        status = "[green]✓ Available[/green]" if tool['available'] else "[red]✗ Not Found[/red]"
        table.add_row(
            tool['tool_name'],
            status,
            tool.get('security_context', '')[:40] + '...'
        )
    
    console.print(table)
    console.print("[dim]Note: AI will use available tools when beneficial but won't depend on them[/dim]")


def get_target_url() -> str:
    """Get target URL from user"""
    console.print("\n[bold cyan]╔═══════════════════════════════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║           TARGET CONFIGURATION                                 ║[/bold cyan]")
    console.print("[bold cyan]╚═══════════════════════════════════════════════════════════════╝[/bold cyan]")
    
    url = Prompt.ask(
        "\n[bold yellow]Enter target URL[/bold yellow]",
        default="https://example.com"
    )
    
    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    return url


def get_advanced_options() -> Dict:
    """Get optional advanced configuration"""
    options = {
        'max_iterations': 10,
        'risk_level': 'medium',
        'use_external_tools': True,
        'use_wordlists': True,
        'output_dir': 'scan_output',
    }
    
    if Confirm.ask("\n[bold yellow]Configure advanced options?[/bold yellow]", default=False):
        # Max iterations
        iterations = Prompt.ask(
            "Maximum attack iterations per strategy",
            default="10"
        )
        options['max_iterations'] = int(iterations)
        
        # Risk level
        risk = Prompt.ask(
            "Risk ceiling",
            choices=["low", "medium", "high"],
            default="medium"
        )
        options['risk_level'] = risk
        
        # External tools
        options['use_external_tools'] = Confirm.ask(
            "Allow AI to use external tools when beneficial?",
            default=True
        )
        
        # Wordlists
        options['use_wordlists'] = Confirm.ask(
            "Allow AI to use dictionary files for fuzzing?",
            default=True
        )
        
        # Output directory
        output = Prompt.ask(
            "Output directory",
            default="scan_output"
        )
        options['output_dir'] = output
    
    return options


def confirm_and_start(mode: str, model: str, provider: str, url: str, options: Dict) -> bool:
    """Display configuration summary and confirm start"""
    console.print("\n[bold cyan]╔═══════════════════════════════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║           CONFIGURATION SUMMARY                                ║[/bold cyan]")
    console.print("[bold cyan]╚═══════════════════════════════════════════════════════════════╝[/bold cyan]")
    
    table = Table(show_header=False)
    table.add_column("Setting", style="cyan", width=20)
    table.add_column("Value", style="green")
    
    mode_names = {
        'web': 'Web Penetration Testing',
        'llm': 'LLM/AI Chatbot Testing',
        'combined': 'Combined (Web + LLM)',
    }
    
    table.add_row("Mode", mode_names.get(mode, mode))
    table.add_row("Target", url)
    table.add_row("AI Model", f"{model} ({provider})")
    table.add_row("Max Iterations", str(options['max_iterations']))
    table.add_row("Risk Level", options['risk_level'])
    table.add_row("External Tools", "Enabled" if options['use_external_tools'] else "Disabled")
    table.add_row("Dictionary Files", "Enabled" if options['use_wordlists'] else "Disabled")
    table.add_row("Output", options['output_dir'])
    
    console.print(table)
    
    console.print("\n[bold yellow]⚠ IMPORTANT: Ensure you have authorization to test the target[/bold yellow]")
    
    return Confirm.ask("\n[bold green]Start security assessment?[/bold green]", default=True)


async def run_web_mode(url: str, model: str, provider: str, options: Dict, logger: Logger):
    """Run web penetration testing mode"""
    from core.agent import SecurityOrchestrator
    
    console.print("\n[bold green]Starting Web Penetration Testing...[/bold green]")
    
    orchestrator = SecurityOrchestrator(
        starting_url=url,
        expand_scope=True,
        enumerate_subdomains=False,
        model=model,
        provider=provider,
        output_dir=options['output_dir'],
        max_iterations=options['max_iterations'],
        debug=False,
        clear_attack_history=True,
        wordlists_dir='lists' if options['use_wordlists'] else None,
        hide_ip=False
    )
    # Run in a separate thread to avoid conflicting with the asyncio loop
    # since the agent uses synchronous Playwright API
    await asyncio.to_thread(orchestrator.run, logger)


async def run_llm_mode(url: str, model: str, provider: str, options: Dict, logger: Logger):
    """Run LLM/AI chatbot testing mode"""
    from playwright.async_api import async_playwright
    from llm.llm import LLM
    from core.ai_red_team_agent import AIRedTeamAgent
    
    console.print("\n[bold green]Starting LLM/AI Chatbot Testing...[/bold green]")
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        page = await browser.new_page()
        
        llm_instance = LLM(
            model_provider=provider,
            model_name=model,
            debug=False
        )
        
        agent = AIRedTeamAgent(
            page=page,
            llm=llm_instance,
            logger_instance=logger,
            max_interactions=options['max_iterations'] * 2,
            risk_ceiling=options['risk_level'],
            timeout_minutes=30.0
        )
        
        result = await agent.run_assessment(url)
        
        # Save results
        output_file = os.path.join(options['output_dir'], 'ai_redteam_report.json')
        os.makedirs(options['output_dir'], exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump({
                'target_url': result.target_url,
                'duration': result.end_time - result.start_time,
                'total_interactions': result.total_interactions,
                'stop_reason': result.stop_reason,
                'success_rate': result.success_rate,
                'vulnerabilities_found': result.vulnerabilities_found,
                'target_model': result.target_model,
                'owasp_findings': result.owasp_findings,
                'recommendations': result.recommendations,
            }, f, indent=2)
        
        console.print(f"\n[bold green]✓ Assessment Complete[/bold green]")
        console.print(f"  Interactions: {result.total_interactions}")
        console.print(f"  Vulnerabilities: {len(result.vulnerabilities_found)}")
        console.print(f"  Report: {output_file}")
        
        await browser.close()


async def run_combined_mode(url: str, model: str, provider: str, options: Dict, logger: Logger):
    """Run combined web + LLM testing mode"""
    console.print("\n[bold green]Starting Combined Testing Mode...[/bold green]")
    console.print("[cyan]Phase 1: Web Application Analysis[/cyan]")
    
    # First run web mode for initial reconnaissance
    await run_web_mode(url, model, provider, options, logger)
    
    console.print("\n[cyan]Phase 2: AI Chatbot Detection and Testing[/cyan]")
    
    # Then run LLM mode if chatbots detected
    await run_llm_mode(url, model, provider, options, logger)


def main():
    """Main entry point with interactive mode selection"""
    print_banner()
    
    logger = Logger()
    
    try:
        # Load external tools and show status
        tools = load_available_tools()
        wordlists = load_available_wordlists()
        
        console.print(f"\n[dim]Found {len([t for t in tools if t['available']])} external tools available[/dim]")
        console.print(f"[dim]Found {len(wordlists)} dictionary files available[/dim]")
        
        # Check for saved configuration
        saved_config = load_configuration()
        use_saved = False
        
        if saved_config:
            display_saved_config(saved_config)
            
            choice = Prompt.ask(
                "\n[bold yellow]Load saved configuration?[/bold yellow]",
                choices=["load", "update", "new"],
                default="load"
            )
            
            if choice == "load":
                use_saved = True
                mode = saved_config.get('mode', 'web')
                model = saved_config.get('model', 'gpt-4o')
                provider = saved_config.get('provider', 'openai')
                
                # Get new target URL
                url = get_target_url()
                
                # Use saved options
                options = {
                    'max_iterations': saved_config.get('max_iterations', 10),
                    'risk_level': saved_config.get('risk_level', 'medium'),
                    'use_external_tools': saved_config.get('use_external_tools', True),
                    'use_wordlists': saved_config.get('use_wordlists', True),
                    'output_dir': saved_config.get('output_dir', 'scan_output'),
                }
                
                console.print("\n[green]✓ Loaded saved configuration[/green]")
            elif choice == "update":
                # Load saved but allow updates
                mode = saved_config.get('mode', 'web')
                model = saved_config.get('model', 'gpt-4o')
                provider = saved_config.get('provider', 'openai')
                
                # Ask if user wants to change mode
                if Confirm.ask("\n[yellow]Change testing mode?[/yellow]", default=False):
                    mode = display_mode_selection()
                    if mode == "exit":
                        console.print("[yellow]Goodbye![/yellow]")
                        return
                
                # Ask if user wants to change model
                if Confirm.ask("[yellow]Change AI model?[/yellow]", default=False):
                    model, provider = display_model_selection()
                
                # Show tools status
                if tools:
                    display_tools_status(tools)
                
                # Get target URL
                url = get_target_url()
                
                # Get advanced options (with saved defaults)
                options = get_advanced_options()
            else:
                # New configuration
                use_saved = False
        
        if not use_saved or saved_config is None or choice == "new":
            # Fresh configuration flow
            mode = display_mode_selection()
            if mode == "exit":
                console.print("[yellow]Goodbye![/yellow]")
                return
            
            model, provider = display_model_selection()
            
            if tools:
                display_tools_status(tools)
            
            url = get_target_url()
            options = get_advanced_options()
        
        # Confirm and start
        if not confirm_and_start(mode, model, provider, url, options):
            console.print("[yellow]Assessment cancelled.[/yellow]")
            return
        
        # Save configuration for next time
        config_to_save = {
            'mode': mode,
            'model': model,
            'provider': provider,
            'last_target': url,
            'max_iterations': options['max_iterations'],
            'risk_level': options['risk_level'],
            'use_external_tools': options['use_external_tools'],
            'use_wordlists': options['use_wordlists'],
            'output_dir': options['output_dir'],
        }
        save_configuration(config_to_save)
        
        # Create output directory
        os.makedirs(options['output_dir'], exist_ok=True)
        
        # Run selected mode
        if mode == "web":
            asyncio.run(run_web_mode(url, model, provider, options, logger))
        elif mode == "llm":
            asyncio.run(run_llm_mode(url, model, provider, options, logger))
        elif mode == "combined":
            asyncio.run(run_combined_mode(url, model, provider, options, logger))
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error: {str(e)}[/red]")
        raise


# Also support command-line arguments for automation
def parse_args():
    """Parse command line arguments for automation support"""
    parser = argparse.ArgumentParser(
        description='AI Security Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-u', '--url', help='Target URL (skips interactive prompt)')
    parser.add_argument('-m', '--model', default='gpt-4o', help='AI model to use')
    parser.add_argument('-p', '--provider', default='auto', help='AI provider')
    parser.add_argument('--mode', choices=['web', 'llm', 'combined'], help='Testing mode')
    parser.add_argument('-i', '--interactive', action='store_true', default=True, 
                        help='Run in interactive mode (default)')
    parser.add_argument('--batch', action='store_true', 
                        help='Run in batch mode (requires --url and --mode)')
    
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    
    if args.batch and args.url and args.mode:
        # Batch mode for automation
        logger = Logger()
        options = {
            'max_iterations': 10,
            'risk_level': 'medium',
            'use_external_tools': True,
            'use_wordlists': True,
            'output_dir': 'scan_output',
        }
        
        provider = args.provider
        if provider == 'auto':
            if args.model.startswith('claude'):
                provider = 'anthropic'
            elif args.model.startswith('gemini'):
                provider = 'gemini'
            else:
                provider = 'openai'
        
        if args.mode == "web":
            asyncio.run(run_web_mode(args.url, args.model, provider, options, logger))
        elif args.mode == "llm":
            asyncio.run(run_llm_mode(args.url, args.model, provider, options, logger))
        elif args.mode == "combined":
            asyncio.run(run_combined_mode(args.url, args.model, provider, options, logger))
    else:
        # Interactive mode (default)
        main()