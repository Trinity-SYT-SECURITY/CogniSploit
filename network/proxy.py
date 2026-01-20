from datetime import datetime
import json
from urllib.parse import urlparse
from typing import Dict, List, Tuple
from playwright.sync_api import sync_playwright, Playwright, Page, Browser, BrowserContext, Request, Response
import logging
from colorlog import ColoredFormatter
import asyncio
import threading
import time
import logging
from colorlog import ColoredFormatter

def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Remove old handlers (if any)
    logger.handlers = []

    # Create colored log format
    formatter = ColoredFormatter(
        "%(log_color)s%(levelname)s:%(name)s:%(message)s",
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    )

    # Create handler and set formatter
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger

# Call at program startup
setup_logger()





class WebProxy:
    """
    Network traffic interceptor for browser-based security assessments.
    
    Implements dual-layer traffic capture using Playwright's built-in
    event system combined with Chrome DevTools Protocol integration.
    Focuses on capturing security-relevant traffic patterns including
    authentication flows, API interactions, and form submissions.
    """

    def __init__(self, starting_url: str, logger):
        """Configure traffic interceptor instance.
        
        Parameters:
            starting_url: Target domain for scope filtering
            logger: Output handler for captured events
        """
        self.requests: List[Dict] = []
        self.responses: List[Dict] = []
        self.captured_traffic: List[Dict] = []
        self.starting_url = starting_url
        self.starting_hostname = urlparse(starting_url).netloc
        self.logger = logger
        self.cdp_client = None
        self.is_capturing = True
        self.request_map = {}
        
    def _test_proxy_connectivity(self) -> bool:
        """
        Test if the proxy server is accessible.
        
        Returns:
            bool: True if proxy is accessible, False otherwise
        """
        import requests
        import socket
        
        proxy_url = "http://127.0.0.1:8081"
        proxy_host = "127.0.0.1"
        proxy_port = 8081
        
        # First check if port is open
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((proxy_host, proxy_port))
            sock.close()
            
            if result != 0:
                # Port is not open
                return False
        except Exception as e:
            self.logger.debug(f"[Proxy] Socket check failed: {str(e)}")
            return False
        
        # Then test with HTTP request
        try:
            self.logger.info(f"[Proxy] Testing connectivity to {proxy_url}")
            
            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            
            response = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=5)
            if response.status_code == 200:
                self.logger.info(f"[Proxy] ✅ Proxy connection successful: {response.json()}")
                return True
            else:
                self.logger.warning(f"[Proxy] ⚠️ Proxy connection test failed with status: {response.status_code}")
                return False
                
        except requests.exceptions.ConnectTimeout:
            self.logger.debug(f"[Proxy] Connection timeout - proxy may be slow")
            return False
        except requests.exceptions.ConnectionError:
            self.logger.debug(f"[Proxy] Connection error - proxy not accessible")
            return False
        except Exception as e:
            self.logger.debug(f"[Proxy] Test error: {str(e)}")
            return False
    
    def check_proxy_available(self) -> bool:
        """
        Check if proxy is available and prompt user if not.
        
        Returns:
            bool: True if proxy is available, False otherwise
        """
        if self._test_proxy_connectivity():
            return True
        
        # Proxy is not available, prompt user
        print("\n" + "="*80)
        print("⚠️  PROXY SERVER NOT DETECTED")
        print("="*80)
        print("\nThe proxy server at http://127.0.0.1:8081 is not running or not accessible.")
        print("\nPlease ensure your proxy server is running before continuing.")
        print("\nCommon proxy tools:")
        print("  - Burp Suite (default port: 8080, but can be configured to 8081)")
        print("  - OWASP ZAP (default port: 8080)")
        print("  - mitmproxy (default port: 8080)")
        print("\nTo start a proxy server:")
        print("  1. Open your proxy tool (Burp Suite, ZAP, etc.)")
        print("  2. Configure it to listen on 127.0.0.1:8081")
        print("  3. Ensure the proxy is running and accepting connections")
        print("\n" + "="*80)
        
        while True:
            user_input = input("\nHave you started the proxy server? (yes/no/retry): ").strip().lower()
            
            if user_input in ['yes', 'y']:
                # User says proxy is ready, test again
                if self._test_proxy_connectivity():
                    print("\n✅ Proxy connection verified! Continuing...\n")
                    return True
                else:
                    print("\n❌ Proxy still not accessible. Please check:")
                    print("   - Is the proxy server running?")
                    print("   - Is it listening on 127.0.0.1:8081?")
                    print("   - Are there any firewall rules blocking the connection?")
                    continue
            elif user_input in ['no', 'n']:
                print("\n⚠️  Continuing without proxy. Network traffic monitoring will be limited.")
                print("   Some features may not work correctly without a proxy server.\n")
                return False
            elif user_input in ['retry', 'r']:
                # Retry connection check
                if self._test_proxy_connectivity():
                    print("\n✅ Proxy connection verified! Continuing...\n")
                    return True
                else:
                    print("\n❌ Proxy still not accessible. Please check your proxy server.\n")
                    continue
            else:
                print("Please enter 'yes', 'no', or 'retry'")

    def create_proxy(self, require_proxy: bool = True) -> Tuple[Browser, BrowserContext, Page, Playwright]:
        """Spawn instrumented browser with traffic capture enabled.
        
        Parameters:
            require_proxy: Enforce proxy availability check
        
        Returns:
            Browser automation stack (browser, context, page, playwright)
        """
        # Check proxy availability first
        proxy_available = False
        if require_proxy:
            proxy_available = self.check_proxy_available()
        else:
            proxy_available = self._test_proxy_connectivity()
        
        # Check if we're in an async context
        try:
            loop = asyncio.get_running_loop()
            self.logger.error("Detected asyncio loop in synchronous context. This may cause issues with Playwright Sync API.")
            raise RuntimeError("Cannot use Playwright Sync API inside an asyncio loop. Consider using Async API or restructuring the code.")
        except RuntimeError as e:
            if "no running event loop" not in str(e).lower():
                raise

        # Close existing browser if it exists
        self.close()

        try:
            self.playwright_instance = sync_playwright().start()
            
            # Configure proxy settings only if proxy is available
            proxy_config = None
            proxy_args = []
            
            if proxy_available:
                proxy_config = {
                    "server": "http://127.0.0.1:8081",
                    "username": None,  # Add if proxy requires authentication
                    "password": None   # Add if proxy requires authentication
                }
                proxy_args = ['--proxy-server=127.0.0.1:8081']
                self.logger.info("[Proxy] Using proxy server for browser connections")
            else:
                self.logger.warning("[Proxy] Proceeding without proxy server")
            
            self.browser = self.playwright_instance.chromium.launch(
                headless=False,
                proxy=proxy_config,
                args=[
                    '--disable-blink-features=AutomationControlled', 
                    '--disable-automation',
                    '--ignore-certificate-errors',
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-http2'  # Fix for Burp Suite RST_STREAM error
                ] + proxy_args
            )
            
            # Create context with needed settings and proxy configuration
            self.context = self.browser.new_context(
                bypass_csp=True,
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                proxy=proxy_config
            )
            
            # Create page
            self.page = self.context.new_page()
            
            # Setup monitoring
            self.setup_monitoring(self.context, self.page)
            
            return self.browser, self.context, self.page, self.playwright_instance
        except Exception as e:
            self.logger.error(f"Failed to create proxy: {str(e)}")
            self.close()
            raise

    def setup_monitoring(self, context: BrowserContext, page: Page):
        """Attach network observers to browser session.
        
        Parameters:
            context: Target browser context
            page: Active page instance
        """
        self._setup_event_listeners(context)
        self._setup_cdp_monitoring(page)
    
    def _setup_event_listeners(self, context: BrowserContext):
        """Register request/response handlers on browser context.
        
        Parameters:
            context: Target for event subscription
        """
        def handle_request(request: Request):
            # Check if we should capture this request
            if self._should_capture_request(request):
                url = request.url
                method = request.method
                resource_type = request.resource_type
                
                # Log proxy usage
                if hasattr(request, 'headers') and 'via' in request.headers:
                    self.logger.info(f"[Proxy] Request routed through proxy: {url} ({method})")
                else:
                    self.logger.info(f"[Proxy] Direct request (no proxy): {url} ({method})")
                
                request_id = f"req_{datetime.now().timestamp()}"
                request_data = {
                    'url': url,
                    'method': method,
                    'headers': dict(request.headers),
                    'timestamp': datetime.now().isoformat(),
                    'resource_type': resource_type,
                    'request_id': request_id,
                    'post_data': request.post_data,
                    'proxy_used': 'via' in request.headers if hasattr(request, 'headers') else False
                }
                
                self.requests.append(request_data)
                self.request_map[url] = request_data
        
        def handle_response(response: Response):
            url = response.url
            status = response.status
            
            if url in self.request_map:
                request_data = self.request_map[url]
                try:
                    response_data = {
                        'url': url,
                        'status': status,
                        'status_text': response.status_text,
                        'headers': dict(response.headers),
                        'timestamp': datetime.now().isoformat(),
                        'request_id': request_data.get('request_id')
                    }
                    
                    if self._should_capture_body(response):
                        try:
                            body = response.body()
                            response_data['body'] = body.decode('utf-8')
                            if 'application/json' in response.headers.get('content-type', ''):
                                try:
                                    json_body = json.loads(response_data['body'])
                                    response_data['json_body'] = json_body
                                except json.JSONDecodeError:
                                    pass
                        except Exception as e:
                            response_data['body_error'] = str(e)
                    
                    self.responses.append(response_data)
                    self.captured_traffic.append({
                        'request': request_data,
                        'response': response_data
                    })
                except Exception as e:
                    self.logger.info(f"Error processing response: {str(e)}")
        
        context.on('request', handle_request)
        context.on('response', handle_response)
    
    def _setup_cdp_monitoring(self, page: Page):
        """
        Set up Chrome DevTools Protocol monitoring as a backup.
        
        Parameters:
            page: Page instance to monitor via CDP
        """
        try:
            self.cdp_client = page.context.new_cdp_session(page)
            self.cdp_client.send('Network.enable')
            self.cdp_requests = {}
            
            def handle_cdp_request(params):
                request_id = params.get('requestId', '')
                request = params.get('request', {})
                url = request.get('url', '')
                method = request.get('method', '')
                
                request_hostname = urlparse(url).netloc
                if request_hostname != self.starting_hostname:
                    return
                
                if any(r['url'] == url for r in self.requests):
                    return
                
                if method == 'POST' or '/api/' in url or url.endswith('.json'):
                    request_data = {
                        'url': url,
                        'method': method,
                        'headers': request.get('headers', {}),
                        'timestamp': datetime.now().isoformat(),
                        'request_id': f"cdp_{request_id}",
                        'post_data': request.get('postData'),
                        'source': 'cdp'
                    }
                    
                    self.requests.append(request_data)
                    self.cdp_requests[request_id] = request_data
            
            def handle_cdp_response(params):
                request_id = params.get('requestId', '')
                if request_id not in self.cdp_requests:
                    return
                
                request_data = self.cdp_requests[request_id]
                response = params.get('response', {})
                url = response.get('url', '')
                
                response_data = {
                    'url': url,
                    'status': response.get('status', 0),
                    'status_text': response.get('statusText', ''),
                    'headers': response.get('headers', {}),
                    'timestamp': datetime.now().isoformat(),
                    'request_id': request_data.get('request_id'),
                    'source': 'cdp'
                }
                
                try:
                    if 'application/json' in response.get('headers', {}).get('content-type', ''):
                        body_response = self.cdp_client.send('Network.getResponseBody', {'requestId': request_id})
                        if body_response and 'body' in body_response:
                            response_data['body'] = body_response['body']
                except Exception:
                    pass
                
                self.responses.append(response_data)
                self.captured_traffic.append({
                    'request': request_data,
                    'response': response_data
                })
                del self.cdp_requests[request_id]
            
            self.cdp_client.on('Network.requestWillBeSent', handle_cdp_request)
            self.cdp_client.on('Network.responseReceived', handle_cdp_response)
        except Exception as e:
            self.logger.info(f"Failed to set up CDP monitoring: {str(e)}")
    
    def _should_capture_request(self, request: Request) -> bool:
        """
        Check if we should capture this request based on type and hostname.
        
        Parameters:
            request: Request to evaluate
            
        Returns:
            bool indicating if request should be captured
        """
        request_hostname = urlparse(request.url).netloc
        url = request.url
        method = request.method
        resource_type = request.resource_type
        
        # Always capture main frame navigation and important requests
        if resource_type == "document":
            return True
            
        # Capture important resource types
        important_types = ['xhr', 'fetch', 'websocket', 'script', 'stylesheet']
        if resource_type in important_types:
            return True
            
        # Capture form submissions and API calls
        is_post = method == 'POST'
        is_api = '/api/' in url or url.endswith('.json')
        is_form = 'multipart/form-data' in request.headers.get('content-type', '')
        
        # Capture all requests to monitor proxy usage comprehensively
        return True
    
    def _should_capture_body(self, response: Response) -> bool:
        """
        Determine if we should capture the response body.
        
        Parameters:
            response: Response to evaluate
            
        Returns:
            bool indicating if body should be captured
        """
        content_type = response.headers.get('content-type', '')
        return 'application/json' in content_type or 'text/html' in content_type
    
    def get_network_data(self) -> Dict:
        """
        Get all captured network data.
        
        Returns:
            Dict containing requests, responses and request-response pairs
        """
        return {
            'requests': self.requests,
            'responses': self.responses,
            'pairs': self.captured_traffic
        }
    
    def save_network_data(self, filepath: str):
        """
        Save captured network data to a JSON file.
        
        Parameters:
            filepath: Path to save JSON file to
        """
        data = {
            'requests': self.requests,
            'responses': self.responses,
            'pairs': self.captured_traffic,
            'timestamp': datetime.now().isoformat()
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
    
    def pretty_print_traffic(self) -> str:
        """
        Pretty print captured traffic.
        
        Returns:
            Formatted string of traffic or None if no traffic captured
        """
        if not self.captured_traffic:
            return None
        
        output = []
        output.append(f"Captured {len(self.captured_traffic)} request-response pairs:")
        
        for idx, pair in enumerate(self.captured_traffic):
            req = pair['request']
            res = pair['response']
            
            output.append(f"\n=== Request {idx+1} ===")
            output.append(f"Type: {req.get('resource_type', 'unknown')}")
            output.append(f"Method: {req['method']}")
            output.append(f"URL: {req['url']}")
            if req.get('post_data'):
                output.append(f"Parameters: {req['post_data']}")
            
            output.append(f"\n--- Response {idx+1} ---")
            output.append(f"Status: {res['status']}")
            
            if 'json_body' in res:
                try:
                    body_str = json.dumps(res['json_body'])[:300]
                    output.append(f"Type: JSON")
                    output.append(f"Body: {body_str}")
                except:
                    if 'body' in res:
                        body_str = res['body'][:300]
                        output.append(f"Type: Raw")
                        output.append(f"Body: {body_str}")
            elif 'body' in res:
                body_str = res['body'][:300]
                output.append(f"Type: Raw") 
                output.append(f"Body: {body_str}")
            
            output.append("\n")
            
        return "\n".join(output)
    
    def clear(self):
        """Clear all captured network data."""
        self.requests = []
        self.responses = []
        self.captured_traffic = []
        self.request_map = {}
        if hasattr(self, 'cdp_requests'):
            self.cdp_requests = {}
            
    def close(self):
        """
        Close the browser and Playwright instance, ensuring all resources are properly released.
        """
        try:
            # Detach CDP client if it exists
            if hasattr(self, 'cdp_client') and self.cdp_client:
                try:
                    self.cdp_client.detach()
                except Exception as e:
                    self.logger.warning(f"Error detaching CDP client: {str(e)}")
                finally:
                    self.cdp_client = None

            # Close the page if it exists
            if hasattr(self, 'page') and self.page:
                try:
                    self.page.close()
                except Exception as e:
                    self.logger.warning(f"Error closing page: {str(e)}")
                finally:
                    self.page = None

            # Close the context if it exists
            if hasattr(self, 'context') and self.context:
                try:
                    self.context.close()
                except Exception as e:
                    self.logger.warning(f"Error closing context: {str(e)}")
                finally:
                    self.context = None

            # Close the browser if it exists
            if hasattr(self, 'browser') and self.browser:
                try:
                    # Add a small delay to ensure pending operations complete
                    time.sleep(1)
                    self.browser.close()
                except Exception as e:
                    self.logger.warning(f"Error closing browser: {str(e)}")
                finally:
                    self.browser = None

            # Stop the Playwright instance if it exists
            if hasattr(self, 'playwright_instance') and self.playwright_instance:
                try:
                    self.playwright_instance.stop()
                except Exception as e:
                    self.logger.warning(f"Error stopping Playwright: {str(e)}")
                finally:
                    self.playwright_instance = None
        except Exception as e:
            self.logger.error(f"Unexpected error during proxy cleanup: {str(e)}")
        finally:
            # Ensure all instance variables are reset to prevent accidental reuse
            self.cdp_client = None
            if hasattr(self, 'page'):
                self.page = None
            if hasattr(self, 'context'):
                self.context = None
            if hasattr(self, 'browser'):
                self.browser = None
            if hasattr(self, 'playwright_instance'):
                self.playwright_instance = None

# --- Monkey patch BrowserActionExecutor.fill to add adaptive fallback when generic selectors fail ---
try:
    from core.tools import BrowserActionExecutor
    from playwright.sync_api import Error as PlaywrightError
except Exception:
    BrowserActionExecutor = None
    PlaywrightError = Exception

if BrowserActionExecutor:
    _original_fill = getattr(BrowserActionExecutor, "fill", None)

    def _adaptive_fill(self, page, selector: str, value: str):
        logger = logging.getLogger("tools")
        # Try original implementation first (if selector is specific enough)
        used_original = False
        if _original_fill and selector and selector not in ("input", "form", "", None):
            try:
                used_original = True
                return _original_fill(self, page, selector, value)
            except Exception as e:
                logger.debug(f"[adaptive_fill] Original fill failed for '{selector}': {e}")

        # If we reach here either selector was generic or original failed
        fallback_tried = False
        candidate_selectors = []
        try:
            # Quick success path if generic selector actually works
            if selector == "input":
                el = page.query_selector("input")
                if el:
                    el.fill(value)
                    return f"[adaptive_fill] Filled first input with value (selector='input')."
            
            # Build candidate selectors (ordered by likelihood)
            candidate_selectors = [
                'input[type="text"]',
                'input:not([type])',
                'input[type="search"]',
                'textarea',
                'input[type="email"]',
                'input[type="password"]',
                'input[type="number"]',
                '[contenteditable="true"]',
                'input[type="url"]',
                'input[type="tel"]'
            ]
            fallback_tried = True
            for cand in candidate_selectors:
                try:
                    el = page.query_selector(cand)
                    if el:
                        # Skip hidden/disabled
                        computed_display = page.evaluate("(s) => { const e=document.querySelector(s); if(!e) return ''; return getComputedStyle(e).display; }", cand)
                        if computed_display == "none":
                            continue
                        is_disabled = page.evaluate("(s) => { const e=document.querySelector(s); return e && e.disabled; }", cand)
                        if is_disabled:
                            continue
                        el.fill(value)
                        return f"[adaptive_fill] Filled '{cand}' with value."
                except Exception:
                    continue

            # As a last attempt, enumerate all possible interactive elements and report
            interactive = page.evaluate("""
                () => {
                  const fields = [];
                  const sels = ['input','textarea','[contenteditable="true"]','select'];
                  for (const s of sels){
                    document.querySelectorAll(s).forEach(el=>{
                      const rect = el.getBoundingClientRect();
                      fields.push({
                        tag: el.tagName.toLowerCase(),
                        type: el.getAttribute('type'),
                        name: el.getAttribute('name'),
                        id: el.id,
                        cls: el.className,
                        placeholder: el.getAttribute('placeholder'),
                        w: Math.round(rect.width),
                        h: Math.round(rect.height)
                      });
                    });
                  }
                  return fields;
                }
            """)
            return f"[adaptive_fill] Failed: no suitable element found for generic selector '{selector}'. Enumerated fields={interactive}"
        except PlaywrightError as e:
            return f"[adaptive_fill] Playwright error while adaptive filling: {e}"
        except Exception as e:
            return f"[adaptive_fill] Unexpected error: {e} (candidates tried: {candidate_selectors if fallback_tried else 'none'})"

    # Replace BrowserActionExecutor.fill only once
    if _original_fill and getattr(BrowserActionExecutor.fill, "__name__", "") != "_adaptive_fill":
        BrowserActionExecutor.fill = _adaptive_fill
        logging.getLogger("tools").info("[adaptive_fill] Patched BrowserActionExecutor.fill with adaptive fallback logic.")