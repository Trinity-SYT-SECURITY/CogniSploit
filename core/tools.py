import sys
import re
import subprocess
import json
import time
from io import StringIO
from llm.llm import LLM
import logging
from utils.logger import Logger
import asyncio
from urllib.parse import quote
from pathlib import Path


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BrowserActionExecutor:
    """
    Browser interaction toolkit for security testing operations.
    Provides methods for page manipulation, script execution, and form interaction.
    """

    def __init__(self, model_provider: str = "openai", model_name: str = None, debug: bool = False):
        self.debug = debug
        self.llm = LLM(model_provider=model_provider, model_name=model_name, debug=debug)
        self.security_actions_performed = 0
        self.logger = logger
        self.min_actions_required = 3
        self.first_navigation = False
        self.current_page = None
        self.current_url = None
        self.injection_attempted = False
        self.wordlist_dir = "lists"
        self.external_tools = self._load_external_tools()
    
    
    
    def _parse_arguments(self, args_str: str) -> list:
        """Parse a string of arguments into a list, respecting quoted strings."""
        args = []
        current_arg = ""
        in_quotes = False
        quote_char = None
        i = 0

        while i < len(args_str):
            char = args_str[i]
            if char in ('"', "'") and (i == 0 or args_str[i-1] != '\\'):
                if not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char:
                    in_quotes = False
                    quote_char = None
                current_arg += char
            elif char == ',' and not in_quotes:
                args.append(current_arg.strip())
                current_arg = ""
            else:
                current_arg += char
            i += 1

        if current_arg:
            args.append(current_arg.strip())

        parsed_args = []
        for arg in Parameters:
            arg = arg.strip()
            if arg == "page":
                parsed_args.append(self.current_page)
            elif arg.startswith('"') and arg.endswith('"'):
                parsed_args.append(arg[1:-1].replace('\\"', '"').replace("\\'", "'"))
            elif arg.startswith("'") and arg.endswith("'"):
                parsed_args.append(arg[1:-1].replace('\\"', '"').replace("\\'", "'"))
            else:
                parsed_args.append(arg)
        return parsed_args
    
    
    def execute_js(self, page, js_code: str) -> str:
        """Execute JavaScript code on the page with enhanced error handling."""
        try:
            # Validate and fix the JavaScript code
            js_code = self._validate_and_fix_js_code(js_code)
            
            if self.debug:
                print(f"[Tools.execute_js] Executing JS code: {js_code}")
            
            # Execute the JavaScript code
            result = page.evaluate(js_code)
            self.security_actions_performed += 1
            
            if self.debug:
                print(f"[Tools.execute_js] JS execution result: {result}")
            
            return result
            
        except Exception as e:
            error_msg = str(e)
            self.logger.error(f"[Tools.execute_js] JavaScript execution failed: {error_msg}")
            
            # Handle specific Playwright errors
            if "SyntaxError" in error_msg:
                # Try to fix common syntax issues
                try:
                    # Remove any problematic characters and try again
                    cleaned_code = re.sub(r'[^\x20-\x7E]', '', js_code)  # Remove non-printable chars
                    cleaned_code = re.sub(r'async\s+', '', cleaned_code)  # Remove async keywords
                    cleaned_code = re.sub(r'await\s+', '', cleaned_code)  # Remove await keywords
                    
                    if self.debug:
                        print(f"[Tools.execute_js] Retrying with cleaned code: {cleaned_code}")
                    
                    result = page.evaluate(cleaned_code)
                    self.security_actions_performed += 1
                    return result
                    
                except Exception as retry_error:
                    self.logger.error(f"[Tools.execute_js] Retry failed: {str(retry_error)}")
                    return f"JavaScript execution failed after cleanup: {str(retry_error)}"
            
            elif "Illegal return statement" in error_msg:
                # Wrap code in a function if it's not already
                if not js_code.strip().startswith("() =>"):
                    wrapped_code = f"() => {{ {js_code} }}"
                    if self.debug:
                        print(f"[Tools.execute_js] Retrying with wrapped code: {wrapped_code}")
                    try:
                        result = page.evaluate(wrapped_code)
                        self.security_actions_performed += 1
                        return result
                    except Exception as wrap_error:
                        self.logger.error(f"[Tools.execute_js] Wrapped code execution failed: {str(wrap_error)}")
                        return f"JavaScript execution failed after wrapping: {str(wrap_error)}"
            
            # If all else fails, return a safe fallback
            try:
                fallback_result = page.evaluate("() => document.documentElement.innerHTML")
                return f"JavaScript execution failed: {error_msg}. Fallback result: {fallback_result[:200]}..."
            except Exception as fallback_error:
                return f"JavaScript execution failed: {error_msg}. Fallback also failed: {str(fallback_error)}"

    def attempt_injection(self, page, element: dict) -> str:
        """Attempt to inject a test payload into the given element and submit."""
        selectors = element.get('selectors') or ([element.get('selector')] if 'selector' in element else [])
        input_type = element.get('inputType', 'text')

        # Load dynamic payloads from wordlists if available
        payloads = self._load_injection_payloads(input_type)
        if not payloads:
            payloads = {"text": ["<script>alert('XSS')</script>"], "password": ["' OR '1'='1"], "default": ["test' --"]}
            payload = payloads.get(input_type, payloads["default"])[0]
        else:
            payload = payloads[0]  # Use first payload for initial attempt

        if not selectors:
            return "Injection failed: No valid selector available"

        self.logger.info(f"[Tools.attempt_injection] Attempting injection on selectors={selectors} with payload: {payload}")
        last_error = None
        for selector in selectors:
            try:
                result = self.fill(page, selector, payload)
                self.injection_attempted = True
                return result
            except Exception as e:
                last_error = e
                self.logger.warning(f"[Tools.attempt_injection] Injection failed for selector '{selector}': {str(e)}. Trying next selector...")
                continue

        self.logger.error(f"[Tools.attempt_injection] Injection failed for all selectors: {selectors}. Last error: {last_error}")
        return f"Injection failed for selectors {selectors}: {str(last_error)}"
    
    
    def _validate_and_fix_js_code(self, js_code: str) -> str:
        """Validate and fix common JavaScript issues for Playwright compatibility."""
        import re
        
        # Remove any leading/trailing whitespace
        js_code = js_code.strip()
        
        # Check for nested tool calls and replace with safe DOM inspection
        if re.search(r'(?:goto|click|fill|submit|execute_js|refresh|presskey)\s*\(', js_code):
            if self.debug:
                print(f"WARNING: Possible nested tool call detected in JS code: {js_code}")
            return "() => document.documentElement.innerHTML"
        
        # Handle return statements
        if js_code.strip().startswith('return '):
            js_code = f"() => {{ {js_code} }}"
        
        # Handle async/await - Playwright doesn't support async functions in evaluate
        if 'await ' in js_code:
            # Replace await with synchronous alternatives where possible
            js_code = re.sub(r'await\s+([a-zA-Z_$][a-zA-Z0-9_$]*\.[a-zA-Z_$][a-zA-Z0-9_$]*\([^)]*\))', r'\1', js_code)
            js_code = re.sub(r'await\s+([a-zA-Z_$][a-zA-Z0-9_$]*)', r'\1', js_code)
            # Remove any remaining async keywords
            js_code = re.sub(r'async\s+', '', js_code)
        
        # Handle console.log - ensure it returns a value
        if 'console.log' in js_code and 'return' not in js_code:
            js_code = js_code.replace('console.log(', 'return console.log(')
        
        # Ensure the code is wrapped in a function if it's not already
        if not js_code.strip().startswith('() =>') and not js_code.strip().startswith('function'):
            # Check if it's already a valid function call
            if not re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(', js_code):
                js_code = f"() => {{ {js_code} }}"
        
        # Final validation - ensure it's a valid function expression
        if not js_code.strip().startswith('() =>') and not js_code.strip().startswith('function'):
            js_code = f"() => {{ {js_code} }}"
        
        return js_code

    def click(self, page, css_selector: str) -> str:
        """Click an element on the page."""
        page.click(css_selector, timeout=5000)
        self.security_actions_performed += 1
        return page.inner_html("html")

    def fill(self, page, css_selector: str, value: str) -> str:
        """Fill a form field and automatically submit if it appears to be an attack payload."""
        try:
            page.wait_for_load_state("domcontentloaded", timeout=30000)
            page_html = page.inner_html("html")
            self.logger.debug(f"[Tools.fill] Page HTML before filling:\n{page_html}")

            if page.locator(css_selector).count() > 0:
                element = page.locator(css_selector).first
                is_visible = element.is_visible()
                is_enabled = element.is_enabled()
                if not is_visible or not is_enabled:
                    raise ValueError(f"Element with selector '{css_selector}' is not visible or enabled")

                element.fill(value, timeout=5000)
                self.logger.debug(f"[Tools.fill] Filled element '{css_selector}' with value: {value}")

                is_attack_payload = any([
                    re.search(r'[<>\"\']', value),
                    re.search(r'(?i)(select|union|sleep|waitfor|delay|exec|xp_cmdshell|from\s)', value),
                    'onerror=' in value.lower() or 'onload=' in value.lower(),
                    len(value) > 50
                ])

                if is_attack_payload:
                    self.logger.debug("[Tools.fill] Detected potential attack payload, attempting auto-submit")
                    return self._attempt_submit_after_fill(page, css_selector)

                self.security_actions_performed += 1
                return f"Form field filled with: {value}\n{page.inner_html('html')}"

            fallback_selectors = ["input[name='query']", "input[name='search']", "input[type='text']", "textarea", "input#username", "input#password"]
            for fallback_selector in fallback_selectors:
                if page.locator(fallback_selector).count() > 0:
                    element = page.locator(fallback_selector).first
                    if element.is_visible():
                        element.fill(value, timeout=5000)
                        self.logger.debug(f"[Tools.fill] Filled fallback selector '{fallback_selector}' with value: {value}")
                        if is_attack_payload:
                            return self._attempt_submit_after_fill(page, fallback_selector)
                        self.security_actions_performed += 1
                        return f"Form field filled with fallback selector: {value}\n{page.inner_html('html')}"

            raise ValueError(f"No suitable input element found with selector '{css_selector}' or fallback selectors")

        except Exception as e:
            self.logger.error(f"[Tools.fill] Execution failed: {str(e)}")
            return f"Execution failed: {str(e)}"
    
    
    def _attempt_submit_after_fill(self, page, css_selector):
        """Attempt to submit a form after filling with an attack payload."""
        submission_attempts = []
        try:
            submit_button = page.locator(
                f"{css_selector} + button[type='submit'], "
                f"{css_selector} ~ button[type='submit'], "
                f"{css_selector} + input[type='submit'], "
                f"{css_selector} ~ input[type='submit'], "
                "button[type='submit'], input[type='submit']"
            ).first
            if submit_button.count() > 0 and submit_button.is_visible() and submit_button.is_enabled():
                submit_button.click(timeout=5000)
                page.wait_for_load_state("networkidle", timeout=10000)
                self.security_actions_performed += 1
                return f"Attack payload submitted: {page.inner_html('html')}"
            submission_attempts.append("Submit button click failed")
        except Exception as e:
            submission_attempts.append(f"Submit button click failed: {str(e)}")

        try:
            form = page.locator(f"{css_selector} >> xpath=ancestor::form").first
            if form.count() > 0:
                form.evaluate("form => form.submit()")
                page.wait_for_load_state("networkidle", timeout=10000)
                self.security_actions_performed += 1
                return f"Attack payload submitted via form: {page.inner_html('html')}"
            submission_attempts.append("JavaScript form submission failed")
        except Exception as e:
            submission_attempts.append(f"JavaScript form submission failed: {str(e)}")

        try:
            element = page.locator(css_selector).first
            element.press("Enter")
            page.wait_for_load_state("networkidle", timeout=10000)
            self.security_actions_performed += 1
            return f"Attack payload filled and Enter pressed: {page.inner_html('html')}"
        except Exception as e:
            submission_attempts.append(f"Enter key press failed: {str(e)}")

        self.logger.debug(f"[Tools.fill] Auto-submit failed after all attempts: {submission_attempts}")
        self.security_actions_performed += 1
        return f"Attack payload filled but submission failed: {page.inner_html('html')}"

    def submit(self, page, css_selector: str = None) -> str:
        """Enhanced form submission with better auto-detection."""
        try:
            page.wait_for_load_state("domcontentloaded", timeout=15000)

            if css_selector:
                form = page.locator(css_selector).first
                if form.count() == 0:
                    raise ValueError(f"No element found with selector: {css_selector}")
                submit_button = form.locator("input[type='submit'], button[type='submit']").first
                if submit_button.count() > 0 and submit_button.is_visible() and submit_button.is_enabled():
                    submit_button.click(timeout=5000)
                    page.wait_for_load_state("networkidle", timeout=10000)
                    self.security_actions_performed += 1
                    return f"Form submitted by clicking submit button in {css_selector}\n{page.inner_html('html')}"
                form.evaluate("form => form.submit()")
                page.wait_for_load_state("networkidle", timeout=10000)
                self.security_actions_performed += 1
                return f"Form submitted using JavaScript for selector: {css_selector}\n{page.inner_html('html')}"

            logger.info("Auto-detecting form submission method...")
            form = page.locator("form").first
            if form.count() > 0:
                submit_button = form.locator("input[type='submit'], button[type='submit']").first
                if submit_button.count() > 0 and submit_button.is_visible() and submit_button.is_enabled():
                    submit_button.click(timeout=5000)
                    page.wait_for_load_state("networkidle", timeout=10000)
                    self.security_actions_performed += 1
                    return f"Auto-submitted form by clicking submit button\n{page.inner_html('html')}"
                form.evaluate("form => form.submit()")
                page.wait_for_load_state("networkidle", timeout=10000)
                self.security_actions_performed += 1
                return f"Auto-submitted form via JavaScript\n{page.inner_html('html')}"

            first_input = page.locator("input, textarea, select").first
            if first_input.count() > 0:
                first_input.press("Enter")
                page.wait_for_load_state("networkidle", timeout=10000)
                self.security_actions_performed += 1
                return f"Simulated Enter key press on input field\n{page.inner_html('html')}"

            button_selectors = ["input[type='submit'], input[type='button'], button", "[onclick*='submit']", "[type='submit'], [type='button']"]
            for selector in button_selectors:
                try:
                    button = page.locator(selector).first
                    if button.count() > 0 and button.is_visible() and button.is_enabled():
                        button.click(timeout=5000)
                        page.wait_for_load_state("networkidle", timeout=10000)
                        self.security_actions_performed += 1
                        return f"Clicked auto-detected button: {selector}\n{page.inner_html('html')}"
                except Exception:
                    continue

            page.evaluate("""() => {
                document.querySelectorAll('form').forEach(f => f.submit());
                document.querySelectorAll('button, input[type="button"]').forEach(b => b.click());
            }""")
            page.wait_for_load_state("networkidle", timeout=10000)
            self.security_actions_performed += 1
            return f"Executed full page JavaScript submission\n{page.inner_html('html')}"

        except Exception as e:
            error_msg = f"Submission failed: {str(e)}. Current page state:\n{page.inner_html('html')}"
            logger.error(error_msg)
            return error_msg

    def presskey(self, page, key: str) -> str:
        """Press a keyboard key."""
        page.keyboard.press(key)
        self.security_actions_performed += 1
        return page.inner_html("html")

    def goto(self, page, url: str) -> str:
        """Navigate to a URL."""
        from pathlib import Path
        dict_files = {"subdomains": "lists/subdomains.txt"}

        if ' ' in url:
            url = re.match(r'([^"\']*?(?:\.html|\.php|\.aspx|\.js|\.css|\.json|\/)?)(?:\s|$)', url).group(1)
            if self.debug:
                print(f"Cleaned URL from natural language: '{url}'")

        if not url.startswith(('http://', 'https://', '/')):
            selected_path = "/"
            for dict_name, file_path in dict_files.items():
                file = Path(file_path)
                if file.exists():
                    with open(file, 'r') as f:
                        subdomains = [line.strip() for line in f if line.strip()]
                        if url.lower() in [s.lower() for s in subdomains]:
                            selected_path = f"/{url.lower()}/"
                            break
                        if any(keyword in url.lower() for keyword in ["doc", "api", "login", "admin"]):
                            for subdomain in subdomains:
                                if any(keyword in subdomain.lower() for keyword in ["doc", "api", "login", "admin"]):
                                    selected_path = f"/{subdomain.lower()}/"
                                    break
                            if selected_path != "/":
                                break
            url = selected_path
            if self.debug:
                print(f"Dynamically selected path: '{url}'")

        url = url.replace('../', '')
        if url.startswith('/'):
            if self.current_url:
                import re
                base_url = re.match(r'(https?://[^/]+)', self.current_url)
                if base_url:
                    url = base_url.group(1) + url
                else:
                    from urllib.parse import urlparse
                    parsed = urlparse(self.current_url)
                    if parsed.netloc:
                        url = f"{parsed.scheme}://{parsed.netloc}{url}"

        self.current_url = url
        self.injection_attempted = False
        if self.first_navigation or '/' in url[8:]:
            self.security_actions_performed += 1
        else:
            self.first_navigation = True

        try:
            page.goto(url)
            self.current_url = url
            return f"Navigated to {self.current_url}\n{page.inner_html('html')}"
        except Exception as e:
            if "/docs/" not in url and "documentation" in url.lower():
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    fallback_url = f"{parsed.scheme}://{parsed.netloc}/docs/"
                    print(f"Primary navigation failed. Trying fallback to {fallback_url}")
                    page.goto(fallback_url)
                    self.current_url = fallback_url
                    return f"Navigated to fallback URL {self.current_url}\n{page.inner_html('html')}"
                except:
                    raise e
            raise

    def refresh(self, page) -> str:
        """Refresh the current page."""
        page.reload()
        self.security_actions_performed += 1
        return page.inner_html("html")

    def python_interpreter(self, code: str) -> str:
        """Execute Python code and capture output."""
        output_buffer = StringIO()
        old_stdout = sys.stdout
        sys.stdout = output_buffer
        try:
            exec(code)
            output = output_buffer.getvalue()
            self.security_actions_performed += 1
            return output
        finally:
            sys.stdout = old_stdout
            output_buffer.close()

    def get_user_input(self, prompt: str) -> str:
        """Get input from user with a timeout."""
        start_time = time.time()
        while time.time() - start_time < 20:  # 20-second timeout
            try:
                return input(prompt)
            except KeyboardInterrupt:
                continue
        return "Timeout: No input received, proceeding with AI action."

    def _load_injection_payloads(self, input_type: str) -> list:
        """Load injection payloads from wordlists based on input type."""
        payloads = []
        wordlist_files = {
            "password": "passwords.txt",
            "text": "xss_payloads.txt",
            "default": "generic_payloads.txt"
        }
        file_name = wordlist_files.get(input_type, wordlist_files["default"])
        file_path = Path(self.wordlist_dir) / file_name
        if file_path.exists():
            with open(file_path, 'r') as f:
                payloads = [line.strip() for line in f if line.strip()]
        return payloads

    def scan_for_injectable_elements(self, page) -> list:
        """Scan the page for forms and injectable elements."""
        self.logger.debug("[Tools.scan_for_injectable_elements] Scanning page for injectable elements")
        injectable_elements = []
        try:
            page.wait_for_load_state("domcontentloaded", timeout=10000)
            js_code = """
            () => {
                const elements = [];
                const forms = document.querySelectorAll('form');
                forms.forEach((form, formIndex) => {
                    const formId = form.id || `form-${formIndex}`;
                    const inputs = form.querySelectorAll('input, textarea, select');
                    inputs.forEach((input, inputIndex) => {
                        if (['submit', 'button', 'hidden'].includes(input.type)) return;
                        if (input.offsetParent === null) return;
                        const selectors = [];
                        if (input.id) selectors.push(`#${input.id}`);
                        if (input.name) selectors.push(`input[name="${input.name}"]`);
                        selectors.push(`form:nth-of-type(${formIndex + 1}) input:nth-of-type(${inputIndex + 1})`);
                        elements.push({
                            type: 'input',
                            formId: formId,
                            selectors: selectors,
                            inputType: input.type || 'text'
                        });
                    });
                });
                const standaloneInputs = document.querySelectorAll('input, textarea, select');
                standaloneInputs.forEach((input, index) => {
                    if (['submit', 'button', 'hidden'].includes(input.type)) return;
                    if (!input.closest('form') && input.offsetParent !== null) {
                        const selectors = [];
                        if (input.id) selectors.push(`#${input.id}`);
                        if (input.name) selectors.push(`input[name="${input.name}"]`);
                        selectors.push(`input:nth-of-type(${index + 1})`);
                        elements.push({
                            type: 'input',
                            formId: null,
                            selectors: selectors,
                            inputType: input.type || 'text'
                        });
                    }
                });
                return elements;
            }
            """
            elements = page.evaluate(js_code)
            injectable_elements.extend(elements)
            self.logger.debug(f"[Tools.scan_for_injectable_elements] Found {len(elements)} injectable elements: {elements}")
        except Exception as e:
            self.logger.error(f"[Tools.scan_for_injectable_elements] Failed to scan: {str(e)}")
        return injectable_elements
    

    def _load_external_tools(self):
        """Load external tools configuration from tools_config.json."""
        try:
            with open("tools_config.json", "r") as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.warning("[Tools._load_external_tools] tools_config.json not found.")
            return []
        except json.JSONDecodeError as e:
            self.logger.error(f"[Tools._load_external_tools] Failed to parse tools_config.json: {str(e)}")
            return []
    
    def _init_external_tool_executor(self):
        """Initialize external tool executor if not already done."""
        if not hasattr(self, 'external_tool_executor'):
            try:
                from tools.external_tool_executor import ExternalToolExecutor
                self.external_tool_executor = ExternalToolExecutor()
            except ImportError as e:
                self.logger.warning(f"[Tools._init_external_tool_executor] Failed to import ExternalToolExecutor: {str(e)}")
                self.external_tool_executor = None
        
        if not hasattr(self, 'wordlist_manager'):
            try:
                from tools.wordlist_manager import WordlistManager
                self.wordlist_manager = WordlistManager()
            except ImportError as e:
                self.logger.warning(f"[Tools._init_external_tool_executor] Failed to import WordlistManager: {str(e)}")
                self.wordlist_manager = None

    def execute_external_tool(self, tool_name: str, parameters: dict) -> str:
        """Execute an external tool with given parameters."""
        self.logger.debug(f"[Tools.execute_external_tool] Attempting to execute tool: {tool_name} with parameters: {parameters}")
        
        # Initialize external tool executor
        self._init_external_tool_executor()
        
        if not self.external_tool_executor:
            # Fallback to old method
            return self._execute_external_tool_fallback(tool_name, parameters)
        
        # Use new external tool executor
        try:
            result = self.external_tool_executor.execute_tool_with_wait(tool_name, parameters)
            
            if result.get("success", False):
                self.security_actions_performed += 1
                output = result.get("output", "")
                execution_time = result.get("execution_time", 0)
                
                # Format output for AI consumption
                formatted_output = f"* EXTERNAL TOOL EXECUTION SUCCESS\nTool: {tool_name}\nExecution time: {execution_time:.2f}s\nOutput:\n{output}"
                
                self.logger.info(f"[Tools.execute_external_tool] {tool_name} executed successfully in {execution_time:.2f}s")
                return formatted_output
            else:
                error_msg = result.get("error", "Unknown error")
                self.logger.error(f"[Tools.execute_external_tool] {tool_name} failed: {error_msg}")
                return f"* EXTERNAL TOOL EXECUTION FAILED\nTool: {tool_name}\nError: {error_msg}"
                
        except Exception as e:
            self.logger.error(f"[Tools.execute_external_tool] Error executing {tool_name}: {str(e)}")
            return f"* EXTERNAL TOOL EXECUTION ERROR\nTool: {tool_name}\nError: {str(e)}"
    
    def _execute_external_tool_fallback(self, tool_name: str, parameters: dict) -> str:
        """Fallback method for external tool execution."""
        tool_config = next((tool for tool in self.external_tools if tool["tool_name"] == tool_name), None)
        if not tool_config:
            return f"Error: Tool {tool_name} not found"

        expected_params = {param["name"] for param in tool_config.get("parameters", [])}
        provided_params = set(parameters.keys())
        if expected_params != provided_params:
            return f"Error: Invalid parameters for {tool_name}. Expected: {expected_params}"

        sanitized_params = {param_name: quote(str(param_value), safe='') if next((p for p in tool_config["parameters"] if p["name"] == param_name), {}).get("type") == "string" else str(param_value) for param_name, param_value in parameters.items()}

        command = tool_config["command"]
        for param_name, param_value in sanitized_params.items():
            command = command.replace(f"{{{param_name}}}", param_value)

        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            self.security_actions_performed += 1
            output = result.stdout + (f"\nErrors: {result.stderr}" if result.stderr else "")
            self.logger.debug(f"[Tools.execute_external_tool] Tool {tool_name} executed: {output[:500]}")
            return output
        except subprocess.TimeoutExpired:
            return f"Error: Tool {tool_name} timed out"
        except subprocess.CalledProcessError as e:
            return f"Error: Tool {tool_name} failed with exit code {e.returncode}: {e.stderr}"
        except FileNotFoundError:
            return f"Error: Tool {tool_name} is not installed"

    def execute_tool(self, page, tool_use):
        """Execute a tool command, checking for injectable elements first or handling external tools."""
        import sqlite3
        from datetime import datetime

        db_path = "security_actions.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS executed_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                url TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                result TEXT
            )
        ''')
        conn.commit()

        try:
            self.logger.debug(f"[Tools.execute_tool] Executing command: {tool_use}")
            self.current_page = page

            cursor.execute("SELECT id FROM executed_actions WHERE action = ? AND url = ?", (tool_use, self.current_url or ""))
            if cursor.fetchone():
                self.logger.info(f"[Tools.execute_tool] Action '{tool_use}' already executed for URL '{self.current_url}'. Skipping.")
                conn.close()
                return f"Action '{tool_use}' already executed. Skipping.\n{page.inner_html('html')}"

            external_tool_match = re.match(r'execute_external_tool\s*\(\s*["\']([^"\']*)["\']\s*,\s*(\{.*?\})\s*\)', tool_use)
            if external_tool_match:
                tool_name = external_tool_match.group(1)
                parameters = json.loads(external_tool_match.group(2))
                result = self.execute_external_tool(tool_name, parameters)
                cursor.execute("INSERT INTO executed_actions (action, url, result) VALUES (?, ?, ?)", (tool_use, self.current_url or "", result))
                conn.commit()
                conn.close()
                return result

            if not self.injection_attempted:
                injectable_elements = self.scan_for_injectable_elements(page)
                if injectable_elements:
                    self.logger.info(f"[Tools.execute_tool] Found {len(injectable_elements)} injectable elements. Attempting injection.")
                    result = self.attempt_injection(page, injectable_elements[0])
                    cursor.execute("INSERT INTO executed_actions (action, url, result) VALUES (?, ?, ?)", ("attempt_injection", self.current_url or "", result))
                    conn.commit()
                    conn.close()
                    return result

            self.injection_attempted = False
            command_match = re.match(r'(\w+)\s*\((.*)\)', tool_use)
            if not command_match:
                conn.close()
                return f"Execution failed: Invalid command format: {tool_use}"

            func_name = command_match.group(1)
            args_str = command_match.group(2)

            if not hasattr(self, func_name):
                conn.close()
                return f"Execution failed: Unknown function: {func_name}"

            func = getattr(self, func_name)
            page_required = func_name in ['goto', 'click', 'fill', 'submit', 'execute_js', 'refresh', 'presskey']

            if not args_str:
                result = func()
            elif page_required:
                # Handle page-required functions like goto, click, fill, etc.
                if args_str.startswith('page'):
                    # Remove 'page,' prefix and parse remaining arguments
                    clean_args = args_str.replace('page,', '').strip()
                    result = self._execute_with_args(func, clean_args)
                else:
                    # Add page as first argument
                    result = self._execute_with_args(func, args_str)
            else:
                result = self._execute_with_args(func, args_str)

            cursor.execute("INSERT INTO executed_actions (action, url, result) VALUES (?, ?, ?)", (tool_use, self.current_url or "", result))
            conn.commit()
            conn.close()
            return result

        except Exception as e:
            self.logger.error(f"[Tools.execute_tool] Execution failed: {str(e)}")
            cursor.execute("INSERT INTO executed_actions (action, url, result) VALUES (?, ?, ?)", (tool_use, self.current_url or "", f"Execution failed: {str(e)}"))
            conn.commit()
            conn.close()
            return f"Execution failed: {str(e)}"

    def _execute_with_args(self, func, args_str):
        """Execute a function with parsed arguments."""
        args = []
        
        # Always add page as first argument for page-required functions
        if self.current_page is None:
            raise ValueError("Page object not available.")
        args.append(self.current_page)
        
        # Clean up args_str by removing 'page,' prefix if present
        clean_args_str = re.sub(r'^page\s*,\s*', '', args_str).strip()
        
        if func.__name__ == 'fill':
            # Handle fill function with selector and value
            match = re.match(r'("[^"]*"|\'[^\']*\')\s*,\s*("[^"]*"|\'[^\']*\')', clean_args_str)
            if not match or len(match.groups()) != 2:
                return f"Execution failed: fill() requires selector and value"
            selector, value = match.groups()
            args.extend([selector.strip('"').strip("'"), value.strip('"').strip("'")])
        elif func.__name__ == 'submit':
            # Handle submit function with optional selector
            match = re.match(r'("[^"]*"|\'[^\']*\')?', clean_args_str)
            if match and match.group(1):
                args.append(match.group(1).strip('"').strip("'"))
        elif func.__name__ == 'goto':
            # Handle goto function with URL
            if clean_args_str:
                # Remove quotes if present
                url = clean_args_str.strip('"').strip("'")
                args.append(url)
        elif func.__name__ == 'click':
            # Handle click function with selector
            if clean_args_str:
                selector = clean_args_str.strip('"').strip("'")
                args.append(selector)
        elif func.__name__ == 'execute_js':
            # Handle execute_js function with JavaScript code
            if clean_args_str:
                js_code = clean_args_str.strip('"').strip("'")
                args.append(js_code)
        elif func.__name__ == 'refresh':
            # Handle refresh function (no additional args needed)
            pass
        elif func.__name__ == 'presskey':
            # Handle presskey function with key
            if clean_args_str:
                key = clean_args_str.strip('"').strip("'")
                args.append(key)
        else:
            # Generic argument parsing for other functions
            if clean_args_str:
                parts = re.split(r',(?=(?:[^\'"]|\'[^\']*\'|"[^"]*")*$)', clean_args_str)
                for part in parts:
                    if part.strip():
                        args.append(self._parse_arg_value(part.strip()))

        self.logger.debug(f"[Tools._execute_with_args] Parsed arguments: {args}")
        return func(*args)
    
    def _find_safe_comma_position(self, args_str):
        """Find a safe position for the first comma that's not inside quotes or HTML tags.
        
        Parameters:
            args_str: String containing argument values
            
        Returns:
            Position of the first safe comma, or -1 if not found
        """
        in_quotes = False
        quote_char = None
        bracket_depth = 0
        escaped = False
        
        for i, char in enumerate(args_str):
            if escaped:
                escaped = False
                continue
                
            if char == '\\':
                escaped = True
                continue
                
            # Track quotes
            if char in ['"', "'"]:
                if not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char:
                    in_quotes = False
                    quote_char = None
            
            # Track angle brackets
            elif char == '<':
                bracket_depth += 1
            elif char == '>':
                bracket_depth = max(0, bracket_depth - 1)
                
            # Check for safe comma
            elif char == ',' and not in_quotes and bracket_depth == 0:
                return i
                
        return -1
        
    def _parse_arg_value(self, arg: str):
        """Parse a single argument value."""
        if arg.startswith('"') and arg.endswith('"'):
            return arg[1:-1]
        if arg.startswith("'") and arg.endswith("'"):
            return arg[1:-1]
        return arg

    def auth_needed(self) -> str:
        """Prompt for user authentication with automatic timeout and AI decision making."""
        page_content = self.current_page.content() if self.current_page else ""
        
        if "captcha" in page_content.lower() or "recaptcha" in page_content.lower():
            self.logger.info("[Tools.auth_needed] CAPTCHA detected, requiring human input.")
            input_msg = "CAPTCHA detected. Please solve and press enter to continue."
            user_input = self.get_user_input(input_msg)
            if "Timeout" in user_input:
                self.logger.info("[Tools.auth_needed] Timeout reached, initiating AI brute-forcing.")
                return self._attempt_brute_force()
            self.security_actions_performed += 1
            return "Authentication completed manually!"
        else:
            self.logger.info("[Tools.auth_needed] Authentication needed. Waiting 15 seconds for manual login...")
            
            # Wait 15 seconds for manual login
            try:
                import time
                start_time = time.time()
                
                # Display countdown
                for remaining in range(15, 0, -1):
                    self.logger.info(f"[Tools.auth_needed] Waiting for manual login... {remaining}s remaining")
                    time.sleep(1)
                
                self.logger.info("[Tools.auth_needed] Timeout reached. AI will now make autonomous decisions for attack strategy.")
                
                # AI autonomous decision making
                return self._ai_autonomous_attack_decision()
                
            except KeyboardInterrupt:
                self.logger.info("[Tools.auth_needed] Manual login detected. Continuing with authenticated session.")
                self.security_actions_performed += 1
                return "Authentication completed manually!"
    
    def _ai_autonomous_attack_decision(self) -> str:
        """AI makes autonomous decisions for attack strategy when authentication times out."""
        self.logger.info("[Tools.auth_needed] AI making autonomous attack decisions...")
        
        # Initialize wordlist manager if available
        self._init_external_tool_executor()
        
        if self.wordlist_manager:
            # Get contextual suggestions for attack strategy
            suggestions = self.wordlist_manager.get_contextual_suggestions("authentication bypass testing")
            
            # Attempt various attack strategies
            attack_strategies = [
                "SQL injection on login forms",
                "Default credential testing",
                "Password brute forcing",
                "Session manipulation",
                "Authentication bypass techniques"
            ]
            
            strategy_info = f"* AI AUTONOMOUS ATTACK DECISION\nAvailable strategies: {', '.join(attack_strategies)}\n{suggestions}"
            
            self.logger.info(f"[Tools.auth_needed] AI attack strategy: {strategy_info}")
            return strategy_info
        else:
            return "* AI AUTONOMOUS ATTACK DECISION\nProceeding with generic attack strategies: SQL injection, default credentials, and brute forcing."

    def _attempt_brute_force(self) -> str:
        """Attempt autonomous brute-forcing using wordlists."""
        injectable_elements = self.scan_for_injectable_elements(self.current_page)
        if not injectable_elements:
            return "No injectable elements found for brute-forcing."
        element = injectable_elements[0]
        passwords = self._load_injection_payloads("password")
        for password in passwords[:5]:  # Limit to 5 attempts to avoid excessive load
            try:
                result = self.fill(self.current_page, element['selectors'][0], password)
                self._attempt_submit_after_fill(self.current_page, element['selectors'][0])
                self.security_actions_performed += 1
                if "success" in result.lower() or "login" in self.current_page.url.lower():
                    return f"Brute-force attempt successful with: {password}\n{self.current_page.inner_html('html')}"
            except Exception:
                continue
        return "Brute-force attempts failed.\n{self.current_page.inner_html('html')}"

    def complete(self) -> str:
        """Mark current task as complete with validation."""
        if self.security_actions_performed < self.min_actions_required:
            return "Completion rejected: Insufficient security testing performed."
        self.security_actions_performed = 0
        return "Completed"

    def _validate_and_fix_selectors(self, tool_use: str) -> str:
        """Validate and fix selectors in a tool use string."""
        import re
        selector_patterns = [
            (r'click\s*\(\s*page\s*,\s*["\']([^"\']*)', r'click(page, "{}")'),
            (r'fill\s*\(\s*page\s*,\s*["\']([^"\']*)["\']', r'fill(page, "{}")'),
            (r'submit\s*\(\s*page\s*,\s*["\']([^"\']*)', r'submit(page, "{}")'),
        ]
        for pattern, template in selector_patterns:
            matches = re.finditer(pattern, tool_use)
            for match in matches:
                selector = match.group(1)
                fixed_selector = self._sanitize_selector(selector)
                if fixed_selector != selector:
                    original = match.group(0)
                    replacement = template.format(fixed_selector)
                    tool_use = tool_use.replace(original, replacement, 1)
        return tool_use

    def _sanitize_selector(self, selector: str) -> str:
        """Sanitize and fix a CSS selector."""
        import re
        if selector.count('"') % 2 != 0:
            selector = selector.replace('"', '')
        if selector.count("'") % 2 != 0:
            selector = selector.replace("'", '')
        selector = re.sub(r'(\w+)\[(\w+)=([^\]]*)?\]', r'\1[\2="\3"]', selector)
        selector = re.sub(r'(\w+)\[(\w+)=([^"\'\]]+)\]', r'\1[\2="\3"]', selector)
        if selector.endswith('='):
            selector += '""'
        if re.search(r'\[\w+$', selector):
            selector += '=""]'
        return selector

    def extract_tool_use(self, action: str) -> str:
        """Extract tool command from action description."""
        import re
        if not action or action.isspace():
            return 'goto(page, "/docs/")'

        self.logger.debug(f"[Tools.extract_tool_use] Raw action input:\n{action}")
        action = re.sub(r'REFORMATTED:\s*', '', action)

        action_match = re.search(r'\*\s*ACTION\s*\n(.*?)(?:\n|$)', action, re.IGNORECASE)
        if action_match:
            raw_tool_use = action_match.group(1).strip()
            raw_tool_use = self._fix_unterminated_strings(raw_tool_use)
            complete_command_match = re.search(r'((?:goto|click|fill|submit|execute_js|refresh|presskey|auth_needed|get_user_input|python_interpreter|complete|execute_external_tool)\s*\([^)]*\))', raw_tool_use)
            if complete_command_match:
                tool_use = complete_command_match.group(1)
            else:
                partial_command_match = re.search(r'((?:goto|click|fill|submit|execute_js|refresh|presskey|auth_needed|get_user_input|python_interpreter|complete|execute_external_tool)\s*\([^)]*)', raw_tool_use)
                if partial_command_match:
                    tool_use = partial_command_match.group(1) + ')'
                else:
                    tool_use = raw_tool_use
            if tool_use.startswith('fill(') and tool_use.count(',') < 2:
                elements = self.scan_for_injectable_elements(self.current_page)
                selector = elements[0]['selectors'][0] if elements else "input[name='query']"
                # Use a raw string for the payload to avoid backslash issues
                payload = r"' OR '1'='1"
                tool_use = f'fill(page, "{selector}", "{payload}")'
            tool_use = self._pre_process_tool_use(tool_use)
            return self._fix_tool_use(tool_use)

        external_cmd_match = re.search(r'(execute_external_tool\s*\(\s*["\'][^"\']+["\']\s*,\s*\{.*?\}\s*\))', action, re.DOTALL)
        if external_cmd_match:
            return external_cmd_match.group(1)

        url_match = re.search(r'(?:navigate|go|visit)\s+(?:to|the)?\s+(?:URL|page|website|site|link|documentation)?\s*(?:at|:)?\s*[\'\"]?(https?://[^\s\'"]+)[\'"]?', action, re.IGNORECASE)
        if url_match:
            return f'goto(page, "{url_match.group(1)}")'

        curl_match = re.search(r'curl\s+(https?://[^\s]+)', action, re.IGNORECASE)
        if curl_match:
            return f'goto(page, "{curl_match.group(1)}")'

        if re.search(r'(?:docs|documentation|api\s*docs)', action, re.IGNORECASE):
            if self.current_url:
                base_url = re.match(r'(https?://[^/]+)', self.current_url)
                if base_url:
                    return f'goto(page, "{base_url.group(1)}/docs/")'
            return 'goto(page, "/docs/")'

        command_with_page_match = re.search(r'((?:goto|click|fill|submit|execute_js|refresh|presskey)\s*\(\s*page\s*,\s*[^)]*\))', action)
        if command_with_page_match:
            return command_with_page_match.group(1)

        command_match = re.search(r'((?:goto|click|fill|submit|execute_js|refresh|presskey|execute_external_tool)\s*\([^)]*\))', action)
        if command_match:
            return self._fix_tool_use(command_match.group(1))

        external_tools_help = "\n" + "\n".join([f"- execute_external_tool(\"{tool['tool_name']}\", {json.dumps({p['name']: p.get('description', '') for p in tool.get('parameters', [])})}) - {tool.get('description', '')} (Context: {tool.get('security_context', '')})" for tool in self.external_tools]) if self.external_tools else "\nNo external tools available."
        prompt = f"""
            Convert the following into a SINGLE valid tool call:
            Tools: goto(page, "URL"), click(page, "selector"), fill(page, "selector", "value"), submit(page, "selector"), execute_js(page, "js_code"), auth_needed(), refresh(page), complete(), execute_external_tool("tool_name", {{parameters}})
            {external_tools_help}
            Text: {action}
            ONLY RETURN the exact code.
        """
        self.logger.debug(f"[Tools.extract_tool_use] Using LLM with prompt:\n{prompt}")
        response = self.llm.output(prompt, temperature=0).strip()
        response = re.sub(r'^```.*?\n|\n```$', '', response)
        response = re.sub(r'^`|`$', '', response)
        return self._fix_tool_use(response)
        
    def _fix_unterminated_strings(self, text: str) -> str:
        """Fix unterminated string literals."""
        import re
        if not text:
            return ""
        if text.count("'") % 2 != 0:
            last_quote_pos = text.rfind("'")
            text = text[:last_quote_pos+1] + "'" + text[last_quote_pos+1:]
        if text.count('"') % 2 != 0:
            last_quote_pos = text.rfind('"')
            text = text[:last_quote_pos+1] + '"' + text[last_quote_pos+1:]
        if '(' in text and ')' not in text:
            text += ')'
        return text
        
    def _pre_process_tool_use(self, tool_use: str) -> str:
        """Pre-process the tool use string."""
        import re
        if not tool_use or tool_use.isspace():
            # Dynamic fallback using a common path from wordlists or context
            new_url = self._suggest_new_url()
            return f'goto(page, "{new_url}")' if new_url else 'goto(page, "/")'

        tool_use = re.sub(r'```.*?```', '', tool_use, flags=re.DOTALL)
        tool_use = re.sub(r'navigate\s+to\s+(?:the\s+)?(.*?)(\.|\s|$)', r'goto(page, "\1")', tool_use, flags=re.IGNORECASE)
        tool_use = re.sub(r'go\s+to\s+(?:the\s+)?(.*?)(\.|\s|$)', r'goto(page, "\1")', tool_use, flags=re.IGNORECASE)
        tool_use = re.sub(r'visit\s+(?:the\s+)?(.*?)(\.|\s|$)', r'goto(page, "\1")', tool_use, flags=re.IGNORECASE)
        tool_use = re.sub(r'curl\s+(https?://[^\s"\']+)', r'goto(page, "\1")', tool_use)
        if 'documentation' in tool_use.lower() and not ('goto' in tool_use or 'click' in tool_use):
            new_url = self._suggest_new_url(terms=['docs', 'documentation'])
            return f'goto(page, "{new_url}")' if new_url else 'goto(page, "/docs/")'
        if ')' in tool_use and tool_use.find(')') < len(tool_use) - 1:
            tool_use = tool_use[:tool_use.find(')') + 1]
        return self._fix_unterminated_strings(tool_use)

    def _suggest_new_url(self, terms=None):
        """Suggest a new URL to explore based on wordlists or common paths."""
        from pathlib import Path
        import random
        common_paths = ["/admin", "/login", "/api"]  # Avoid hardcoding /docs here
        if terms:
            common_paths = [p for p in common_paths if any(term in p.lower() for term in terms)]
        
        subdomains_file = Path(self.wordlist_dir) / "subdomains.txt"
        if subdomains_file.exists():
            with open(subdomains_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
                if subdomains:
                    return f"/{random.choice(subdomains)}/"
        
        if self.current_url:
            import re
            base_url = re.match(r'(https?://[^/]+)', self.current_url)
            if base_url:
                return base_url.group(1) + random.choice(common_paths) if common_paths else "/"
        
        return random.choice(common_paths) if common_paths else "/"
    
    def _fix_tool_use(self, tool_use: str) -> str:
        """Fix common issues with tool use extraction."""
        import re
        if not tool_use or tool_use.isspace():
            return self._dom_inspection_tool_use()
        tool_use = tool_use.replace('\\"', '"').replace("\\'", "'")
        if re.search(r'(goto|click|fill|submit|execute_js|refresh|presskey)\s*\(\s*page\s*,\s*.*?(goto|click|fill|submit|execute_js|refresh|presskey)', tool_use):
            if 'execute_js' in tool_use:
                return 'execute_js(page, "() => document.documentElement.innerHTML")'
            return 'goto(page, "/docs/")'
        tool_use = self._fix_unterminated_strings(tool_use)
        if not any(cmd in tool_use for cmd in ['goto(', 'click(', 'fill(', 'execute_js(', 'submit(', 'auth_needed(', 'refresh(', 'complete(', 'execute_external_tool(']):
            url_match = re.search(r'(https?://[^\s"\']+)', tool_use)
            if url_match:
                return f'goto(page, "{url_match.group(1)}")'
            if any(term in tool_use.lower() for term in ['doc', 'documentation', 'api', 'swagger']):
                return 'goto(page, "/docs/")'
            if any(term in tool_use.lower() for term in ['login', 'sign in', 'authenticate']):
                return 'goto(page, "/login/")'
            return self._dom_inspection_tool_use()
        for func in ['goto', 'click', 'fill', 'submit', 'execute_js', 'refresh', 'presskey']:
            if func + '(' in tool_use and 'page' not in tool_use:
                parens_pos = tool_use.find('(')
                tool_use = tool_use[:parens_pos+1] + 'page, ' + tool_use[parens_pos+1:]
        if '(' in tool_use and tool_use.count('(') != tool_use.count(')'):
            tool_use += ')' * (tool_use.count('(') - tool_use.count(')'))
        if tool_use == 'refresh(page)':
            return self._dom_inspection_tool_use()
        if not any(valid_tool in tool_use for valid_tool in ['goto(', 'click(', 'fill(', 'execute_js(', 'submit(', 'auth_needed(', 'refresh(', 'complete(', 'execute_external_tool(']):
            return self._dom_inspection_tool_use()
        return tool_use

    def _dom_inspection_js(self) -> str:
        """Return JS that enumerates inputs/forms for DOM inspection."""
        return "() => Array.from(document.querySelectorAll('input, textarea, form')).map(el => ({tag: el.tagName, id: el.id, name: el.name, type: el.type}))"
    

    def _dom_inspection_tool_use(self) -> str:
        """Return a properly quoted execute_js tool call for DOM inspection."""
        js_code = self._dom_inspection_js()
        return f"execute_js(page, {json.dumps(js_code)})"