import base64
import os
import logging
import re
from google import genai
from google.genai import types
import time
from typing import Dict, List, Optional, Any
from openai import OpenAI
from anthropic import Anthropic
from utils.constants import OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY
from utils.utils import get_base64_image
import requests
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
import random

import nest_asyncio
import asyncio
from playwright.async_api import async_playwright
import atexit

# Allow nested event loops
nest_asyncio.apply()


def rate_limit_handler(max_retries: int = 5, base_delay: float = 1.0, max_delay: float = 60.0):
    """
    Decorator for handling API rate limits with exponential backoff.
    
    Implements retry logic with increasing delays when rate limits are hit.
    Uses jitter to prevent thundering herd problems.
    
    Parameters:
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay cap in seconds
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            delay = base_delay
            last_error = None
            
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    error_str = str(e).lower()
                    
                    # Check for rate limit indicators
                    rate_limit_indicators = [
                        'rate limit', 'rate_limit', '429',
                        'resource_exhausted', 'quota exceeded',
                        'too many requests', 'retry after'
                    ]
                    
                    is_rate_limit = any(ind in error_str for ind in rate_limit_indicators)
                    
                    if is_rate_limit and attempt < max_retries - 1:
                        # Add jitter to prevent synchronized retries
                        jitter = random.uniform(0, 0.5)
                        wait_time = min(delay + jitter, max_delay)
                        
                        logger.warning(f"Rate limit hit, waiting {wait_time:.1f}s before retry {attempt + 1}/{max_retries}")
                        time.sleep(wait_time)
                        
                        # Exponential backoff
                        delay = min(delay * 2, max_delay)
                        last_error = e
                    else:
                        raise e
            
            if last_error:
                raise last_error
        return wrapper
    return decorator


class LLM:
    """
    Multi-provider AI interface for security assessment automation.
    
    Abstracts interactions with various LLM backends (OpenAI, Anthropic,
    Gemini, Ollama, LiteLLM) through a unified API. Provides specialized
    prompting strategies optimized for penetration testing workflows.
    """

    def __init__(self, model_provider: str = "openai", model_name: str = None, debug: bool = False):
        """Configure multi-provider AI backend.
        
        Parameters:
            model_provider: Backend service (openai/anthropic/gemini/ollama/litellm)
            model_name: Override default model selection
            debug: Activate diagnostic logging
        """
        self.model_provider = model_provider.lower()
        if self.model_provider not in ["openai", "anthropic", "gemini", "ollama", "litellm"]:
            raise ValueError(f"Unsupported model provider: {self.model_provider}")
        self.model_name = model_name
        self.debug = debug
        
        # LiteLLM configuration
        self.litellm_api_base = os.getenv("LITELLM_API_BASE", "")
        self.litellm_api_key = os.getenv("LITELLM_API_KEY", "")
        
        # Initialize token and request tracking for Gemini
        self.token_count = 0
        self.request_count = 0
        self.last_minute_time = time.time()
        self.daily_request_count = 0
        self.last_day_time = time.time()
        
        # Initialize OpenAI client
        self.openai_client = OpenAI(api_key=OPENAI_API_KEY)
        
        # Initialize Anthropic client if API key is available
        if ANTHROPIC_API_KEY:
            self.anthropic_client = Anthropic(api_key=ANTHROPIC_API_KEY)
        else:
            self.anthropic_client = None
            if model_provider == "anthropic":
                if self.debug:
                    print("Warning: Anthropic API key not found but Anthropic provider requested. Some functionality may not work.")
        
        # Initialize Gemini client (new google.genai API)
        if GEMINI_API_KEY and model_provider == "gemini":
            os.environ["GEMINI_API_KEY"] = GEMINI_API_KEY
            self.gemini_client = genai.Client(api_key=GEMINI_API_KEY)
            self.gemini_model_name = model_name or "gemini-2.5-flash"
        else:
            self.gemini_client = None
            self.gemini_model_name = None
            if model_provider == "gemini" and self.debug:
                logger.warning("Gemini API key not found but Gemini provider requested.")
        
        # Initialize Ollama for local models
        if model_provider == "ollama":
            try:
                import ollama
                self.ollama = ollama
                self.ollama_model = model_name or 'gpt-oss:20b'
                self.ollama_base = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
                self.system_prompt = "You are a concise security testing assistant."
            except ImportError:
                raise ImportError("Ollama library not found. Please install it with 'pip install ollama'.")
        else:
            self.ollama = None
        
        # Initialize LiteLLM provider
        if model_provider == "litellm":
            import requests
            self.requests = requests
            
            # Validate configuration
            if not self.litellm_api_base:
                raise ValueError("LITELLM_API_BASE environment variable is not set. Please set it in your .env file.")
            if not self.litellm_api_key:
                raise ValueError("LITELLM_API_KEY environment variable is not set. Please set it in your .env file.")
            
            # Ensure API base ends with correct endpoint
            if not self.litellm_api_base.endswith('/'):
                self.litellm_api_base += '/'
            if not self.litellm_api_base.endswith('v1/chat/completions'):
                if not self.litellm_api_base.endswith('v1/'):
                    self.litellm_api_base += 'v1/'
                if not self.litellm_api_base.endswith('chat/completions'):
                    self.litellm_api_base += 'chat/completions'
            self.litellm_model = model_name or os.getenv("LITELLM_MODEL", "gpt-4o")
            if self.debug:
                logger.info(f"LiteLLM configured: API Base={self.litellm_api_base}, Model={self.litellm_model}")
            logger.info(f"[LLM] LiteLLM initialized with API Base: {self.litellm_api_base[:50]}..., Model: {self.litellm_model}")
        
        # Set default model names
        self.openai_model = model_name if model_name and model_provider == "openai" else "gpt-4"
        self.anthropic_model = model_name if model_name and model_provider == "anthropic" else "claude-3-sonnet-20240229"
        self.gemini_model = model_name if model_name and model_provider == "gemini" else "gemini-2.5-pro"
        
        # Set model-specific configurations
        self.model_config = self._get_model_config()
        
        # Set system prompts (with provider-specific optimizations)
        self._set_system_prompts()
        if self.debug:
            logger.info(f"Initialized LLM with provider: {self.model_provider}, model: {self._get_default_model()}")
                
            
    def _get_default_model(self) -> str:
        """Helper to get the default model based on provider."""
        if self.model_provider == "openai":
            return self.openai_model
        elif self.model_provider == "anthropic":
            return self.anthropic_model
        elif self.model_provider == "gemini":
            return self.gemini_model
        return "unknown"
    
    def _get_model_config(self) -> Dict[str, Any]:
        """Get configuration settings for the selected model."""
        configs = {
            # Claude 3 Sonnet
            'claude-3-sonnet-20240229': {
                'max_tokens': 4096,
                'temperature': 0.7,
                'supports_hybrid_reasoning': True,
                'context_window': 200000,
            },
            # Claude 3 Opus
            'claude-3-opus-20240229': {
                'max_tokens': 4096,
                'temperature': 0.7,
                'supports_hybrid_reasoning': True,
                'context_window': 200000,
            },
            # GPT-4o (updated from gpt-4)
            'gpt-4o': {
                'max_tokens': 16384,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 128000,
            },
            # GPT-3.5 
            'gpt-3.5-turbo': {
            'max_tokens': 4096,
            'temperature': 0.7,
            'supports_hybrid_reasoning': False,
            'context_window': 16385,
            },
            # Gemini models with limits
            'gemini-2.5-pro': {
                'rpm': 5,
                'tpm': 250000,
                'rpd': 100,
                'max_tokens': 8192,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 32768,
            },
            'gemini-2.5-flash': {
                'rpm': 10,
                'tpm': 250000,
                'rpd': 250,
                'max_tokens': 8192,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 32768,
            },
            'gemini-2.5-flash-lite': {
                'rpm': 15,
                'tpm': 250000,
                'rpd': 1000,
                'max_tokens': 8192,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 32768,
            },
            'gemini-2.0-flash': {
                'rpm': 15,
                'tpm': 1000000,
                'rpd': 200,
                'max_tokens': 8192,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 32768,
            },
            'gemini-2.0-flash-lite': {
                'rpm': 30,
                'tpm': 1000000,
                'rpd': 200,
                'max_tokens': 8192,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 32768,
            },
            # Ollama (local, no limits)
            'gpt-oss:20b': {
                'max_tokens': None,  # No limit for local
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': None,  # Dependent on model
            },
        }
        
        if self.model_provider == "anthropic":
            return configs.get(self.anthropic_model, {
                'max_tokens': 4096,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 100000,
            })
        elif self.model_provider == "gemini":
            return configs.get(self.gemini_model, {
                'rpm': 15,
                'tpm': 250000,
                'rpd': 1000,
                'max_tokens': 8192,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 32768,
            })
        elif self.model_provider == "ollama":
            return configs.get(self.ollama_model, {
                'max_tokens': 8192,  # Adjust as needed based on your hardware capabilities
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 131072,  # Maximum supported context window
            })

        else:  # Default to OpenAI
            return configs.get(self.openai_model, {
                'max_tokens': 16384,
                'temperature': 0.7,
                'supports_hybrid_reasoning': False,
                'context_window': 128000,
            })
    
    def _set_system_prompts(self):
        """Configure provider-specific prompt templates."""
        # Core identity and mission (REWRITTEN - distinct from similar projects)
        base_prompt = """
        You operate as an autonomous web application security analyst with expertise in offensive security techniques. Your mission is to methodically assess the target application through systematic exploration, vulnerability identification, and controlled exploitation validation. You have authorization to perform comprehensive penetration testing within the defined scope.
        """
        # Shared tool definitions (consistent across providers)
        tool_definitions = """
        <tools>
        IMPORTANT: ALL tools that interact with page elements require the 'page' parameter as their FIRST parameter.

        - execute_js(page, js_code): Run JavaScript code on the page via Playwright's evaluate function
        - click(page, css_selector): Click on an element matching the CSS selector
        - fill(page, css_selector, value): Fill a form field with the specified value
        - auth_needed(): Signal that authentication is required
        - get_user_input(prompt): Request input from the user
        - presskey(page, key): Press a keyboard key
        - submit(page, css_selector): Submit a form
        - goto(page, url): Navigate to a different URL
        - refresh(page): Refresh the current page
        - python_interpreter(code): Execute Python code
        - complete(): Mark the current test as complete ONLY after at least 3 security testing actions

        EXAMPLES OF PROPER TOOL USAGE:
        - goto(page, "https://example.com/api/docs")
        - click(page, "a[href='/login']")
        - fill(page, "#username", "' OR 1=1 --")
        - execute_js(page, "() => {{ return document.cookie }}")
        </tools>
        
        <output_format>
        YOU MUST STRICTLY FORMAT YOUR RESPONSE EXACTLY AS FOLLOWS:

        * DISCUSSION
        [A few sentences about your security analysis and testing strategy]

        * ACTION
        [EXACTLY ONE tool command with proper syntax and all required parameters]

        VALID TOOL COMMANDS - USE THESE EXACT FORMATS:
        - goto(page, "https://example.com")
        - click(page, "a.nav-link")
        - fill(page, "#input-field", "test value")
        - submit(page, "form#login")
        - execute_js(page, "() => {{ return document.cookie }}")
        - auth_needed()
        - refresh(page)
        - complete()
        - python_interpreter("print('test')")
        - get_user_input("Enter value:")
        - presskey(page, "Enter")
        </output_format>
        """
        # OpenAI-specific prompt (COMPLETELY REWRITTEN)
        self.openai_system_prompt = f"""
        {base_prompt}
        {tool_definitions}
        
        ## Data Streams
        You receive structured intelligence about the target:
        
        1. **DOM Snapshot**: Sanitized HTML representation of the active page
        2. **Extracted Metadata**: Links, form elements, and potential injection points
        3. **Traffic Capture**: HTTP request/response pairs from network monitoring
        4. **Attack Sequence**: Step-by-step testing instructions to execute
        
        ## Capability Set
        Your toolkit enables comprehensive web interaction:
        
        **Browser Control:**
        - `execute_js(code)` → Inject and evaluate JavaScript via Playwright's evaluate API. Return values explicitly; console.log won't work.
        - `click(selector)` → Simulate user click on matched element
        - `fill(selector, data)` → Populate input field with specified payload
        - `submit(selector)` → Trigger form submission
        - `goto(target_url)` → Navigate browser to new location
        - `refresh()` → Reload current page state
        - `presskey(key)` → Simulate keyboard input
        
        **System Operations:**
        - `python_interpreter(script)` → Execute arbitrary Python (requests, nmap, etc.)
        - `auth_needed()` → Pause for manual authentication
        - `get_user_input(query)` → Request operator input
        - `complete()` → Signal test completion (only after confirmed exploitation)
        
        ## Response Protocol
        Structure every response as:
        
        * DISCUSSION
        Brief analysis of observations and planned next action.
        
        * ACTION
        Single tool invocation with correct syntax.
        
        ## Engagement Rules
        
        1. Execute the provided attack sequence systematically
        2. Validate findings with reproducible proof-of-concept
        3. Prioritize high-impact vulnerabilities (CVSS 7.0+)
        4. Avoid false positives - missing headers alone are not exploits
        5. Iterate approaches when initial attempts fail
        6. Document exploitation chain with precision
        7. Only invoke `complete()` after demonstrating actual impact
        8. Apply advanced techniques: polyglot payloads, encoding bypass, chained exploits
        """
        
        # Claude-specific prompt (optimized for Claude's capabilities)
        self.anthropic_system_prompt = f"""
        {base_prompt}
        {tool_definitions}

        <security_task>
        Analyze websites for vulnerabilities including but not limited to:
        - SQL injection
        - Cross-site scripting (XSS)
        - Cross-site request forgery (CSRF)
        - Server-side request forgery (SSRF)
        - Insecure deserialization
        - Security misconfigurations
        </security_task>
        
        <input_format>
        You will receive:
        - HTML content of the current page
        - Structured page data (links, forms, etc.)
        - Network traffic (requests/responses)
        - Testing plan to follow
        </input_format>
        
        <tools>
        IMPORTANT: ALL tools that interact with page elements require the 'page' parameter as their FIRST parameter.

        - execute_js(page, js_code): Run JavaScript code on the page via Playwright's evaluate function
        - click(page, css_selector): Click on an element matching the CSS selector
        - fill(page, css_selector, value): Fill a form field with the specified value
        - auth_needed(): Signal that authentication is required
        - get_user_input(prompt): Request input from the user
        - presskey(page, key): Press a keyboard key
        - submit(page, css_selector): Submit a form
        - goto(page, url): Navigate to a different URL
        - refresh(page): Refresh the current page
        - python_interpreter(code): Execute Python code
        - complete(): Mark the current test as complete ONLY after at least 3 security testing actions

        EXAMPLES OF PROPER TOOL USAGE:
        - goto(page, "https://example.com/api/docs")
        - click(page, "a[href='/login']")
        - fill(page, "#username", "' OR 1=1 --")
        - execute_js(page, "() => {{ return document.cookie }}")
        </tools>
        
        <output_format>
        YOU MUST STRICTLY FORMAT YOUR RESPONSE EXACTLY AS FOLLOWS:

        * DISCUSSION
        [A few sentences about your security analysis and testing strategy]

        * ACTION
        [EXACTLY ONE tool command with proper syntax and all required parameters]

        VALID TOOL COMMANDS - USE THESE EXACT FORMATS:
        - goto(page, "https://target.com") - Navigate to a URL
        - click(page, "selector") - Click an element
        - fill(page, "selector", "payload") - Fill a form field with a payload (e.g., fill(page, "input[name='query']", "' OR '1'='1") for SQL Injection; ensure the selector is a single quoted string)
        - submit(page, "form") - Submit a form (use this after filling form fields to send the payload to the server)
        - execute_js(page, "code") - Run JavaScript code
        - auth_needed() - Signal authentication is needed
        - refresh(page) - Refresh the page
        - complete() - Mark test as complete
        - python_interpreter("print('test')")
        - get_user_input("Enter value:")
        - presskey(page, "Enter")

        Every tool that interacts with the page MUST have 'page' as its FIRST PARAMETER.

        Examples:

        * DISCUSSION
        I've examined the login form and found it accepts any input without validation. I'll test SQL injection by attempting to bypass authentication.

        * ACTION
        fill(page, "#username", "' OR 1=1 --")

        -----

        * DISCUSSION
        I need to check for XSS vulnerabilities in the comment form. I'll try inserting a basic XSS payload.

        * ACTION
        fill(page, "#comment", "<script>alert(document.cookie)</script>")

        CRITICALLY IMPORTANT REQUIREMENTS:
        1. ALWAYS include both DISCUSSION and ACTION sections with the exact format above
        2. ALWAYS include the 'page' parameter as the FIRST PARAMETER for page interaction tools
        3. ALWAYS use proper CSS selectors with balanced quotes (e.g., "a[href='docs/']" NOT "a[href=docs/]")
        4. NEVER use tool commands without all required parameters
        5. ALWAYS perform at least 3 meaningful security tests before using complete()
        6. NEVER format your response in any other way - only use the exact format above
        7. NEVER include natural language instead of a proper command in the ACTION section
        </output_format>
        
        <javascript_guidelines>
        When writing JavaScript for execute_js():
        1. DO NOT use standalone "return" statements - they cause "Illegal return statement" errors
        2. ALWAYS wrap code in an anonymous function: `() => {{ /* your code */ }}`
        3. RETURN values explicitly from the anonymous function
        4. For async operations, use `async () => {{ /* await code */ }}`

        CORRECT: 
        ```javascript
        () => {{ 
          const result = document.querySelector('h1').textContent; 
          return result; 
        }}
        ```

        INCORRECT: 
        ```javascript
        return document.querySelector('h1').textContent;
        ```

        CORRECT for async:
        ```javascript
        async () => {{
          const response = await fetch('/api/data');
          const data = await response.json();
          return data;
        }}
        ```

        Security-focused JavaScript examples:
        
        1. DOM-based XSS testing:
        ```javascript
        () => {{
          // Check if URL parameters are reflected without sanitization
          const params = new URLSearchParams(window.location.search);
          const reflectedParams = [];
          params.forEach((value, key) => {{
            const elements = document.querySelectorAll(`*:contains("${{value}}")`);
            if (elements.length > 0) reflectedParams.push(key);
          }});
          return reflectedParams;
        }}
        ```

        2. CSRF token extraction:
        ```javascript
        () => {{
          const csrfTokens = [];
          // Check for common CSRF token field names
          const tokenFields = document.querySelectorAll('input[name*="csrf"], input[name*="token"], meta[name*="csrf"]');
          tokenFields.forEach(field => {{
            csrfTokens.push({{name: field.name || field.getAttribute('name'), value: field.value || field.getAttribute('content')}});
          }});
          return csrfTokens;
        }}
        ```
        </javascript_guidelines>
        
        <rules>
        - Follow the testing plan step by step
        - Use provided tools only with correct parameter format (page must be first parameter)
        - Verify vulnerabilities with concrete proof
        - Focus on high-impact issues
        - Document exploitation steps precisely
        - Call complete() only after at least 3 meaningful security testing actions
        - Use advanced techniques (polyglots, custom scripts)
        - Do not repeat unsuccessful actions
        - Use selectors from the page summary
        - ALWAYS format your response with DISCUSSION and ACTION sections
        - ALWAYS follow JavaScript guidelines to avoid execution errors
        - ALWAYS use properly formatted and balanced quotation marks in selectors
        - ALWAYS provide descriptive security analysis in the DISCUSSION section
        </rules>

        <selector_formatting>
        For all CSS selectors, ensure proper formatting:
        
        1. ALWAYS balance quotation marks in attribute selectors:
           - CORRECT: a[href="docs/"]
           - INCORRECT: a[href=docs/]
           
        2. ALWAYS escape quotes within quoted attributes:
           - CORRECT: input[placeholder="Enter your name"]
           - CORRECT: input[placeholder='Enter your name']
           
        3. For attribute selectors, always include quotes around attribute values:
           - CORRECT: button[type="submit"]
           - INCORRECT: button[type=submit]
           
        4. Complex attribute selectors should use proper nesting and quotes:
           - CORRECT: div[class="user-form"] input[name="password"]
           - INCORRECT: div[class=user-form] input[name=password]
        </selector_formatting>
        """
        # Gemini-specific prompt
        self.gemini_system_prompt = f"""
        {base_prompt}
        {tool_definitions}
        
        <security_task>
        Analyze websites for vulnerabilities including but not limited to:
        - SQL injection
        - Cross-site scripting (XSS)
        - Cross-site request forgery (CSRF)
        - Server-side request forgery (SSRF)
        - Insecure deserialization
        - Security misconfigurations
        </security_task>
        
        <input_format>
        You will receive:
        - HTML content of the current page
        - Structured page data (links, forms, etc.)
        - Network traffic (requests/responses)
        - Testing plan to follow
        </input_format>
        
        <rules>
        - Follow the testing plan step by step
        - Use provided tools only with correct parameter format (page must be first parameter for page interactions)
        - Verify vulnerabilities with concrete proof
        - Focus on high-impact issues
        - Document exploitation steps precisely
        - Call complete() only after at least 3 meaningful security testing actions
        - Use advanced techniques (polyglots, custom scripts)
        - Do not repeat unsuccessful actions
        - Use selectors from the page summary
        </rules>
        """

        # Ollama-specific prompt (optimized for its reasoning structure)
        self.ollama_system_prompt = f"""
        You are a security testing assistant. Your primary goal is to actively explore and test all reachable pages of a website for vulnerabilities. 
        Follow these steps:
        1. Analyze the current page for links, forms, and interactive elements.
        2. Click links to navigate to new pages and repeat the analysis.
        3. Test forms for vulnerabilities like SQL injection and XSS by filling them with malicious payloads and submitting them.
        4. Use tools like `goto`, `click`, `fill`, and `submit` to interact with the page.
        5. Do not overthink or delay actions. Perform one action at a time and immediately decide the next step.

        <tools>
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
        </tools>

        <output_format>
        ALWAYS format your response as:
        * DISCUSSION
        [Briefly explain your analysis and the next action.]
        * ACTION
        [Exactly ONE tool command.]
        </output_format>

        <rules>
        - Always click links and explore new pages.
        - Test forms for vulnerabilities like SQL injection and XSS.
        - Perform one action at a time and decide the next step immediately.
        - Do not stay on one page unless all actions are exhausted.
        - Use tools effectively and avoid unnecessary delays.
        - Call complete() only after at least 3 meaningful actions or a confirmed vulnerability.
        </rules>
        """
    
        if self.model_provider == "openai":
            self.system_prompt = self.openai_system_prompt
        elif self.model_provider == "anthropic":
            self.system_prompt = self.anthropic_system_prompt
        elif self.model_provider == "gemini":
            self.system_prompt = self.gemini_system_prompt
        elif self.model_provider == "ollama":
            self.system_prompt = self.ollama_system_prompt
        elif self.model_provider == "litellm":
            # LiteLLM uses OpenAI-compatible format, so use OpenAI prompt
            self.system_prompt = self.openai_system_prompt
        else:
            raise ValueError(f"Unsupported model provider: {self.model_provider}")

    def reason(self, messages: List[Dict[str, str]], reasoning: str = "medium") -> str:
        """Execute multi-turn conversation with reasoning capabilities.
        
        Parameters:
            messages: Conversation thread as role/content pairs
            reasoning: Cognitive effort (low/medium/high)
        
        Returns:
            Model completion text
        """
        if self.model_provider == "openai":
            return self._openai_reason(messages, reasoning)
        elif self.model_provider == "anthropic":
            return self._anthropic_reason(messages)
        elif self.model_provider == "gemini":
            return self._gemini_reason(messages)
        elif self.model_provider == "ollama":
            return self._ollama_reason(messages)
        elif self.model_provider == "litellm":
            return self._litellm_reason(messages)
        else:
            raise ValueError(f"Unsupported model provider: {self.model_provider}")
        

    def _ollama_reason(self, messages: List[Dict[str, str]]) -> str:
        """Ollama-specific implementation of reasoning."""
        if not self.ollama:
            raise ValueError("Ollama not initialized. Check if the library is installed.")
        
        # Ollama chat expects list of dicts with 'role' and 'content'
        response = self.ollama.chat(model=self.ollama_model, messages=messages)
        return response['message']['content']
    
    def _openai_reason(self, messages: List[Dict[str, str]], reasoning: str = "medium") -> str:
        """OpenAI-specific implementation of reasoning."""
        # Extract model name from messages or use default
        model = self.openai_model
        
        # Handle reasoning effort for o1/o3 models
        params = {
            "model": model,
            "messages": messages,
            "temperature": self.model_config.get('temperature', 0.7),
        }
        
        # Add reasoning_effort for o1/o3 models
        if "o1" in model.lower() or "o3" in model.lower():
            reasoning_map = {"low": "low", "medium": "medium", "high": "high"}
            params["reasoning_effort"] = reasoning_map.get(reasoning, "medium")
        
        response = self.openai_client.chat.completions.create(**params)
        return response.choices[0].message.content
    
    def _litellm_reason(self, messages: List[Dict[str, str]]) -> str:
        """LiteLLM-specific implementation of reasoning."""
        if not self.litellm_api_base or not self.litellm_api_key:
            raise ValueError("LiteLLM not configured. Check LITELLM_API_BASE and LITELLM_API_KEY.")
        
        headers = {
            "Authorization": f"Bearer {self.litellm_api_key}",
            "Content-Type": "application/json"
        }
        
        # Normalize payload for model-specific requirements
        payload = {
            "model": self.litellm_model,
            "messages": messages,
            "temperature": self.model_config.get('temperature', 0.7),
            "max_tokens": self.model_config.get('max_tokens', 4096)
        }
        
        # Handle Gemini-specific parameters if model is Gemini
        if "gemini" in self.litellm_model.lower():
            # Disable safety filters for security testing
            payload["safety_settings"] = [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            ]
            payload["generation_config"] = {
                "temperature": payload["temperature"],
                "top_p": 0.95,
                "top_k": 64,
                "max_output_tokens": payload["max_tokens"]
            }
        
        max_retries = 3
        retry_delay = 1
        
        for attempt in range(max_retries):
            try:
                response = self.requests.post(
                    self.litellm_api_base,
                    headers=headers,
                    json=payload,
                    timeout=120
                )
                
                if response.status_code == 401:
                    error_msg = f"LiteLLM authentication failed (401 Unauthorized). Please check your LITELLM_API_KEY."
                    logger.error(error_msg)
                    if self.debug:
                        logger.error(f"API Base: {self.litellm_api_base}")
                        logger.error(f"Response: {response.text[:200]}")
                    raise ValueError(error_msg)
                elif response.status_code != 200:
                    error_msg = f"LiteLLM API request failed with status {response.status_code}: {response.text[:200]}"
                    if self.debug:
                        logger.error(error_msg)
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        retry_delay *= 2
                        continue
                    else:
                        response.raise_for_status()
                
                result = response.json()
                return result["choices"][0]["message"]["content"]
            
            except Exception as e:
                if self.debug:
                    logger.error(f"LiteLLM request error on attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    retry_delay *= 2
                else:
                    raise
        
        raise Exception(f"Failed to make LiteLLM API request after {max_retries} attempts")
    
    def _enforce_gemini_limits(self, estimated_tokens: int):
        """Enforce Gemini rate limits before making a call."""
        current_time = time.time()
        
        # Daily reset
        if current_time - self.last_day_time >= 86400:  # 24 hours
            self.daily_request_count = 0
            self.last_day_time = current_time
        
        # Minute reset
        if current_time - self.last_minute_time >= 60:
            self.token_count = 0
            self.request_count = 0
            self.last_minute_time = current_time
        
        # Check daily request limit
        if self.daily_request_count >= self.model_config['rpd']:
            remaining_time = 86400 - (current_time - self.last_day_time)
            logger.warning(f"Daily request limit reached. Waiting {remaining_time:.2f} seconds until reset.")
            time.sleep(remaining_time)
            self.daily_request_count = 0
            self.last_day_time = time.time() + remaining_time  # Adjust for sleep
        
        # Check per-minute request limit
        if self.request_count >= self.model_config['rpm'] / 2:
            remaining_time = 60 - (current_time - self.last_minute_time)
            logger.warning(f"Half of RPM limit reached. Waiting {remaining_time:.2f} seconds until minute reset.")
            time.sleep(remaining_time)
            self.request_count = 0
            self.token_count = 0
            self.last_minute_time = time.time() + remaining_time
        
        # Check per-minute token limit
        if self.token_count + estimated_tokens >= self.model_config['tpm'] / 2:
            remaining_time = 60 - (current_time - self.last_minute_time)
            logger.warning(f"Half of TPM limit reached. Waiting {remaining_time:.2f} seconds until minute reset.")
            time.sleep(remaining_time)
            self.token_count = 0
            self.request_count = 0
            self.last_minute_time = time.time() + remaining_time

    def _gemini_reason(self, messages: List[Dict[str, str]]) -> str:
        """Gemini-specific implementation of reasoning with rate limiting."""
        if not self.gemini_client:
            raise ValueError("Gemini client not initialized. Check GEMINI_API_KEY.")
        
        # Combine messages into a single prompt with system prompt
        prompt = self.system_prompt + "\n\n" + "\n".join(
            [f"{msg['role'].upper()}: {msg['content']}" for msg in messages]
        )
        
        # Enforce rate limits before call
        self._enforce_gemini_limits(len(prompt))
        
        max_retries = 10
        base_delay = 5
        
        for attempt in range(max_retries):
            try:
                response = self.gemini_client.models.generate_content(
                    model=self.gemini_model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        max_output_tokens=self.model_config.get('max_tokens', 8192),
                        temperature=self.model_config.get('temperature', 0.7),
                        safety_settings=[
                            types.SafetySetting(category="HARM_CATEGORY_HARASSMENT", threshold="BLOCK_NONE"),
                            types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH", threshold="BLOCK_NONE"),
                            types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="BLOCK_NONE"),
                            types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE"),
                        ]
                    )
                )
                response_text = response.text.strip()
                # Update counts after successful call
                self._update_gemini_counts(len(prompt) + len(response_text))
                # Check for quota in response
                if "quota" in response_text.lower():
                    logger.warning("Quota limit detected in Gemini response. Waiting 60 seconds before continuing...")
                    time.sleep(60)
                    continue  # Retry the request after waiting
                return response_text
            
            except Exception as e:
                error_message = str(e).lower()
                # Check for quota in error message
                if "quota" in error_message or "429" in error_message:
                    logger.warning("Quota/Rate limit detected in Gemini error. Waiting 60 seconds before continuing...")
                    time.sleep(60)
                    continue  # Retry the request after waiting

                # Check for overloaded/503 errors
                if "overloaded" in error_message or "503" in error_message:
                    logger.warning(f"Gemini service overloaded (503). Waiting {base_delay * (attempt + 1)}s before retry...")
                    time.sleep(base_delay * (attempt + 1))
                    continue

                is_rate_limit = "rate" in error_message
                if is_rate_limit and attempt < max_retries - 1:
                    delay = (base_delay * (2 ** attempt)) + random.uniform(0, 1)
                    logger.warning(f"Gemini rate limit hit. Retrying in {delay:.2f} seconds...")
                    time.sleep(delay)
                else:
                    logger.error(f"Gemini reasoning failed: {str(e)}")
                    raise

    def _anthropic_reason(self, messages: List[Dict[str, str]]) -> str:
        """Anthropic-specific implementation of reasoning."""
        # Convert message format if needed
        anthropic_messages = self._convert_to_anthropic_format(messages)
        
        # Get model-specific configuration
        max_tokens = self.model_config.get('max_tokens', 4096)
        temperature = self.model_config.get('temperature', 0.5)
        supports_hybrid_reasoning = self.model_config.get('supports_hybrid_reasoning', False)
        
        # Create request parameters
        params = {
            "model": self.anthropic_model,
            "max_tokens": max_tokens,
            "messages": anthropic_messages,
            "temperature": temperature,
        }
        
        # Add hybrid reasoning if supported
        if supports_hybrid_reasoning:
            params["thinking"] = {"type": "enabled", "budget_tokens": 2000}
            # When extended thinking is enabled, temperature must be set to 1.0
            # according to Anthropic's API error message
            params["temperature"] = 1.0
        
        # Use enhanced retry logic with rate limit handling
        max_retries = 7
        base_delay = 5  # seconds
        
        for attempt in range(max_retries):
            try:
                if self.debug and attempt > 0:
                    print(f"Anthropic reasoning retry attempt {attempt+1}/{max_retries}")
                
                # For retries, reduce the context size to help with rate limits
                if attempt > 0 and not supports_hybrid_reasoning:
                    # Create a reduced version of messages for retries
                    # Keep system message and last few messages to maintain context
                    reduced_messages = []
                    
                    # Find how many messages to keep (progressively reduce with each retry)
                    keep_count = max(3, len(anthropic_messages) - (attempt * 2))
                    reduced_messages = anthropic_messages[-keep_count:]
                    
                    # Update params with reduced messages
                    params["messages"] = reduced_messages
                    
                    if self.debug:
                        reduction = (1 - len(reduced_messages) / len(anthropic_messages)) * 100
                        print(f"Reduced message count by {reduction:.0f}% to handle rate limits")
                
                # Make the API call
                response = self.anthropic_client.messages.create(**params)
                
                # Extract and return the response
                if supports_hybrid_reasoning:
                    # When extended thinking is enabled, the response structure is different
                    # For ThinkingBlock objects, the content is in the 'thinking' attribute
                    return response.content[0].thinking
                else:
                    # Standard response handling
                    return response.content[0].text
                    
            except Exception as e:
                # Enhanced rate limit error detection
                is_rate_limit = (
                    hasattr(e, 'type') and getattr(e, 'type', None) == 'rate_limit_error' or
                    hasattr(e, 'status_code') and getattr(e, 'status_code', None) == 429 or
                    '429' in str(e) or 'rate_limit' in str(e).lower()
                )
                
                if is_rate_limit and attempt < max_retries - 1:
                    # Longer exponential backoff with jitter
                    import random
                    delay = (base_delay * (2 ** attempt)) + random.uniform(0, 1)
                    print(f"Rate limit hit in reasoning. Retrying in {delay:.2f} seconds with reduced context...")
                    time.sleep(delay)
                else:
                    # For other exceptions or final attempt, re-raise
                    raise
    
    def evaluate_attack(self, tool_command: str, response: str, plan_title: str) -> bool:
        """Use Gemini to evaluate if an attack was successful based on tool command and response."""
        if not self.gemini_client:
            raise ValueError("Gemini client not initialized. Check Gemini_API_KEY.")
        
        evaluation_prompt = f"""
        You are a security expert evaluating the success of a security test. Based on the following details, determine if the attack was successful. Return "SUCCESS" if it succeeded, "FAIL" otherwise, with a brief explanation.

        Plan: {plan_title}
        Tool Command: {tool_command}
        Response: {response}
        
        Examples of success:
        - XSS: Response contains executed script (e.g., "alert executed")
        - SQL Injection: Response shows unauthorized data or login bypass
        - SSRF: Response includes internal server data
        
        Format your response as:
        RESULT: [SUCCESS or FAIL]
        EXPLANATION: [Brief reasoning]"""
        max_retries = 10
        base_delay = 5

        for attempt in range(max_retries):
            try:
                response = self.gemini_client.models.generate_content(
                    model=self.gemini_model_name,
                    contents=evaluation_prompt,
                    config=types.GenerateContentConfig(
                        max_output_tokens=512,
                        temperature=0.5,
                        safety_settings=[
                            types.SafetySetting(category="HARM_CATEGORY_HARASSMENT", threshold="BLOCK_NONE"),
                            types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH", threshold="BLOCK_NONE"),
                            types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="BLOCK_NONE"),
                            types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE"),
                        ]
                    )
                )
                result_text = response.text.strip()
                if "RESULT: SUCCESS" in result_text.upper():
                    logger.info(f"Gemini confirmed success for {tool_command}: {result_text}")
                    return True
                else:
                    logger.info(f"Gemini evaluated as fail for {tool_command}: {result_text}")
                    return False
            
            except Exception as e:
                error_message = str(e).lower()
                
                # Check for overloaded/503 errors
                if "overloaded" in error_message or "503" in error_message:
                    logger.warning(f"Gemini service overloaded (503) in evaluation. Waiting {base_delay * (attempt + 1)}s before retry...")
                    time.sleep(base_delay * (attempt + 1))
                    continue

                is_rate_limit = "rate" in error_message or "429" in error_message
                if is_rate_limit and attempt < max_retries - 1:
                    import random
                    delay = (base_delay * (2 ** attempt)) + random.uniform(0, 1)
                    logger.warning(f"Gemini rate limit hit in evaluation. Retrying in {delay:.2f} seconds...")
                    time.sleep(delay)
                else:
                    logger.error(f"Gemini evaluation failed: {str(e)}")
                    return False  # Default to fail on error
    
    
    def _convert_to_anthropic_format(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Convert OpenAI message format to Anthropic format if needed.
        
        Parameters:
            messages: List of messages in OpenAI format
            
        Returns:
            List of messages in Anthropic format
        """
        # Extract system message if present
        system_message = None
        anthropic_messages = []
        
        for message in messages:
            if message["role"] == "system":
                system_message = message["content"]
            else:
                # Copy the message as is (both APIs use "user" and "assistant" roles)
                anthropic_messages.append(message)
        
        return anthropic_messages

    def output(self, message: str, temperature: float = 0.0) -> str:
        """Send single prompt and retrieve completion.
        
        Parameters:
            message: User prompt content
            temperature: Randomness factor (0.0 = deterministic)
        
        Returns:
            Model completion text
        """
        if self.model_provider == "openai":
            return self._openai_output(message, temperature)
        elif self.model_provider == "anthropic":
            return self._anthropic_output(message, temperature)
        elif self.model_provider == "gemini":
            return self._gemini_output(message, temperature)
        elif self.model_provider == "ollama":
            return self._ollama_output(message)
        elif self.model_provider == "litellm":
            return self._litellm_output(message, temperature)
        else:
            raise ValueError(f"Unsupported model provider: {self.model_provider}")

    def _ollama_output(self, message: str) -> str:
        """Ollama-specific implementation of output."""
        if not self.ollama:
            raise ValueError("Ollama not initialized. Check if the library is installed.")
        
        response = self.ollama.chat(model=self.ollama_model, messages=[{'role': 'user', 'content': message}])
        return response['message']['content']

    def _update_gemini_counts(self, used_tokens: int):
        """Update token and request counts after a successful call."""
        self.token_count += used_tokens
        self.request_count += 1
        self.daily_request_count += 1


    def _gemini_output(self, message: str, temperature: float = 0.7) -> str:
        """Gemini-specific implementation of output with rate limiting and error handling."""
        if not self.gemini_client:
            raise ValueError("Gemini client not initialized. Check GEMINI_API_KEY.")
        
        # Enforce rate limits before call
        self._enforce_gemini_limits(len(message))
        
        max_retries = 10
        base_delay = 5
        
        for attempt in range(max_retries):
            try:
                response = self.gemini_client.models.generate_content(
                    model=self.gemini_model_name,
                    contents=message,
                    config=types.GenerateContentConfig(
                        max_output_tokens=self.model_config.get('max_tokens', 8192),
                        temperature=temperature,
                        safety_settings=[
                            types.SafetySetting(category="HARM_CATEGORY_HARASSMENT", threshold="BLOCK_NONE"),
                            types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH", threshold="BLOCK_NONE"),
                            types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="BLOCK_NONE"),
                            types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE"),
                        ]
                    )
                )
                # Check if response contains valid text
                if hasattr(response, 'candidates') and response.candidates:
                    candidate = response.candidates[0]
                    if candidate.content and candidate.content.parts:
                        response_text = candidate.content.parts[0].text.strip() if candidate.content.parts[0].text else ""
                    else:
                        response_text = ""
                        logger.warning(f"Gemini response contains no valid text part (finish_reason: {candidate.finish_reason}). Attempt {attempt + 1}/{max_retries}")
                else:
                    response_text = ""
                    logger.warning(f"Gemini response has no candidates or content. Attempt {attempt + 1}/{max_retries}")
                
                # Update counts after successful call
                self._update_gemini_counts(len(message) + len(response_text))
                
                # Check for quota in response
                if "quota" in response_text.lower():
                    logger.warning("Quota limit detected in Gemini response. Waiting 60 seconds before continuing...")
                    time.sleep(60)
                    continue  # Retry the request after waiting
                
                if not response_text and attempt < max_retries - 1:
                    delay = (base_delay * (2 ** attempt)) + random.uniform(0, 1)
                    logger.warning(f"No valid text returned from Gemini. Retrying in {delay:.2f} seconds...")
                    time.sleep(delay)
                    continue
                
                return response_text if response_text else "No valid response generated."
            
            except Exception as e:
                error_message = str(e).lower()
                # Check for quota in error message
                if "quota" in error_message or "429" in error_message:
                    logger.warning("Quota/Rate limit detected in Gemini error. Waiting 60 seconds before continuing...")
                    time.sleep(60)
                    continue  # Retry the request after waiting
                
                # Check for overloaded/503 errors
                if "overloaded" in error_message or "503" in error_message:
                    logger.warning(f"Gemini service overloaded (503) in output. Waiting {base_delay * (attempt + 1)}s before retry...")
                    time.sleep(base_delay * (attempt + 1))
                    continue
                    
                is_rate_limit = "rate" in error_message
                if is_rate_limit and attempt < max_retries - 1:
                    delay = (base_delay * (2 ** attempt)) + random.uniform(0, 1)
                    logger.warning(f"Gemini rate limit hit (non-quota). Retrying in {delay:.2f} seconds...")
                    time.sleep(delay)
                else:
                    logger.error(f"Gemini output failed: {str(e)}")
                    raise

        logger.error(f"Max retries exceeded for Gemini output. Returning empty response.")
        return ""
    
    
    def _openai_output(self, message: str, temperature: float = 0.0) -> str:
        """OpenAI-specific implementation of output."""
        response = self.openai_client.chat.completions.create(
            model="gpt-4o",
            temperature=temperature,
            messages=[{"role": "user", "content": message}],
        )
        return response.choices[0].message.content
    
    def _litellm_output(self, message: str, temperature: float = 0.0) -> str:
        """LiteLLM-specific implementation of output."""
        if not self.litellm_api_base or not self.litellm_api_key:
            raise ValueError("LiteLLM not configured. Check LITELLM_API_BASE and LITELLM_API_KEY.")
        
        headers = {
            "Authorization": f"Bearer {self.litellm_api_key}",
            "Content-Type": "application/json"
        }
        
        # Normalize payload for model-specific requirements
        payload = {
            "model": self.litellm_model,
            "messages": [{"role": "user", "content": message}],
            "temperature": temperature,
            "max_tokens": self.model_config.get('max_tokens', 4096)
        }
        
        # Handle Gemini-specific parameters if model is Gemini
        if "gemini" in self.litellm_model.lower():
            # Disable safety filters for security testing
            payload["safety_settings"] = [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            ]
            payload["generation_config"] = {
                "temperature": temperature,
                "top_p": 0.95,
                "top_k": 64,
                "max_output_tokens": payload["max_tokens"]
            }
        
        max_retries = 3
        retry_delay = 1
        
        for attempt in range(max_retries):
            try:
                response = self.requests.post(
                    self.litellm_api_base,
                    headers=headers,
                    json=payload,
                    timeout=120
                )
                
                if response.status_code == 401:
                    error_msg = f"LiteLLM authentication failed (401 Unauthorized). Please check your LITELLM_API_KEY."
                    logger.error(error_msg)
                    if self.debug:
                        logger.error(f"API Base: {self.litellm_api_base}")
                        logger.error(f"Response: {response.text[:200]}")
                    raise ValueError(error_msg)
                elif response.status_code != 200:
                    error_msg = f"LiteLLM API request failed with status {response.status_code}: {response.text[:200]}"
                    if self.debug:
                        logger.error(error_msg)
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        retry_delay *= 2
                        continue
                    else:
                        response.raise_for_status()
                
                result = response.json()
                return result["choices"][0]["message"]["content"]
            
            except Exception as e:
                if self.debug:
                    logger.error(f"LiteLLM request error on attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    retry_delay *= 2
                else:
                    raise
        
        raise Exception(f"Failed to make LiteLLM API request after {max_retries} attempts")

    def _anthropic_output(self, message: str, temperature: float = 0.7) -> str:
        """Anthropic-specific implementation of output."""
        if not self.anthropic_client:
            raise ValueError("Anthropic client not initialized. Check ANTHROPIC_API_KEY.")
        
        max_retries = 7
        base_delay = 5
        
        for attempt in range(max_retries):
            try:
                if self.debug and attempt > 0:
                    print(f"Anthropic API retry attempt {attempt+1}/{max_retries}")
                
                if attempt > 0:
                    message_length = len(message)
                    reduction_factor = min(0.25 * attempt, 0.75)
                    reduced_length = int(message_length * (1 - reduction_factor))
                    reduced_message = message[:reduced_length] + "\n[Content truncated due to rate limits]"
                    
                    if self.debug:
                        print(f"Reduced message by {reduction_factor*100:.0f}% to handle rate limits")
                
                    response = self.anthropic_client.messages.create(
                        model=self.anthropic_model,
                        max_tokens=self.model_config.get('max_tokens', 4096),
                        temperature=temperature,
                        messages=[{"role": "user", "content": reduced_message}],
                    )
                else:
                    response = self.anthropic_client.messages.create(
                        model=self.anthropic_model,
                        max_tokens=self.model_config.get('max_tokens', 4096),
                        temperature=temperature,
                        messages=[{"role": "user", "content": message}],
                    )
                    
                return response.content[0].text
            
            except Exception as e:
                is_rate_limit = "rate" in str(e).lower() or "429" in str(e)
                if is_rate_limit and attempt < max_retries - 1:
                    delay = (base_delay * (2 ** attempt)) + random.uniform(0, 1)
                    logger.warning(f"Anthropic rate limit hit. Retrying in {delay:.2f} seconds...")
                    time.sleep(delay)
                else:
                    logger.error(f"Anthropic output failed: {str(e)}")
                    raise