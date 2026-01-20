"""
Two-Factor Authentication Support
Enables testing of applications with 2FA/TOTP authentication
"""
import time
import hmac
import struct
import hashlib
import base64
import logging
from typing import Dict, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


def hotp(key: bytes, counter: int, digits: int = 6) -> str:
    """
    Generate HOTP (HMAC-based One-Time Password).
    
    Parameters:
        key: Secret key as bytes
        counter: Counter value
        digits: Number of digits in OTP (default 6)
        
    Returns:
        OTP string
    """
    # Convert counter to 8 bytes
    counter_bytes = struct.pack('>Q', counter)
    
    # Generate HMAC-SHA1
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    
    # Dynamic truncation
    offset = hmac_hash[-1] & 0x0f
    binary = struct.unpack('>I', hmac_hash[offset:offset + 4])[0] & 0x7fffffff
    
    # Generate OTP
    otp = binary % (10 ** digits)
    return str(otp).zfill(digits)


def totp(key: bytes, time_step: int = 30, digits: int = 6, t0: int = 0) -> str:
    """
    Generate TOTP (Time-based One-Time Password).
    
    Parameters:
        key: Secret key as bytes
        time_step: Time step in seconds (default 30)
        digits: Number of digits in OTP (default 6)
        t0: Start time (Unix timestamp, default 0)
        
    Returns:
        OTP string
    """
    current_time = int(time.time())
    counter = (current_time - t0) // time_step
    return hotp(key, counter, digits)


def decode_secret(secret: str) -> bytes:
    """
    Decode a base32-encoded secret key.
    
    Parameters:
        secret: Base32-encoded secret string
        
    Returns:
        Decoded key as bytes
    """
    # Remove spaces and convert to uppercase
    secret = secret.replace(' ', '').upper()
    
    # Add padding if necessary
    padding = 8 - (len(secret) % 8)
    if padding != 8:
        secret += '=' * padding
    
    return base64.b32decode(secret)


def generate_totp(secret: str, digits: int = 6) -> str:
    """
    Generate a TOTP code from a secret.
    
    Parameters:
        secret: Base32-encoded secret string
        digits: Number of digits in OTP (default 6)
        
    Returns:
        TOTP code string
    """
    key = decode_secret(secret)
    return totp(key, digits=digits)


def get_remaining_seconds() -> int:
    """Get remaining seconds until next TOTP code"""
    return 30 - (int(time.time()) % 30)


@dataclass
class AuthConfig:
    """Configuration for authentication flow"""
    login_type: str = "form"  # form, oauth, api
    login_url: str = ""
    credentials: Dict[str, str] = field(default_factory=dict)
    totp_secret: Optional[str] = None
    
    # Login flow steps (natural language instructions)
    login_flow: list = field(default_factory=list)
    
    # Success detection
    success_condition: Dict[str, str] = field(default_factory=dict)
    
    # Cookie/session handling
    session_storage: bool = True
    cookie_domain: Optional[str] = None


class TwoFactorAuthenticator:
    """
    Handles 2FA authentication for security testing.
    
    Supports:
    - TOTP (Google Authenticator, Authy, etc.)
    - SMS (requires external callback)
    - Email (requires external callback)
    """
    
    def __init__(self, page=None, llm=None):
        """
        Initialize authenticator.
        
        Parameters:
            page: Playwright page object for browser interaction
            llm: LLM instance for intelligent form detection
        """
        self.page = page
        self.llm = llm
        self.auth_config: Optional[AuthConfig] = None
        self.authenticated = False
        self.session_data: Dict[str, Any] = {}
    
    def configure(self, config: AuthConfig):
        """Set authentication configuration"""
        self.auth_config = config
        logger.info(f"[2FA] Configured authentication for {config.login_url}")
    
    def generate_totp_code(self) -> Optional[str]:
        """Generate current TOTP code from configured secret"""
        if not self.auth_config or not self.auth_config.totp_secret:
            logger.warning("[2FA] No TOTP secret configured")
            return None
        
        try:
            code = generate_totp(self.auth_config.totp_secret)
            remaining = get_remaining_seconds()
            logger.info(f"[2FA] Generated TOTP code (valid for {remaining}s)")
            return code
        except Exception as e:
            logger.error(f"[2FA] Failed to generate TOTP: {str(e)}")
            return None
    
    async def perform_login(self) -> bool:
        """
        Perform the complete login flow including 2FA.
        
        Returns:
            True if login successful, False otherwise
        """
        if not self.auth_config:
            logger.error("[2FA] No authentication configuration set")
            return False
        
        if not self.page:
            logger.error("[2FA] No browser page available")
            return False
        
        try:
            # Navigate to login page
            await self.page.goto(self.auth_config.login_url)
            await self.page.wait_for_load_state('networkidle')
            
            # Execute login flow steps
            for step in self.auth_config.login_flow:
                await self._execute_login_step(step)
            
            # Check for 2FA prompt
            if await self._detect_2fa_prompt():
                logger.info("[2FA] 2FA prompt detected, entering code")
                await self._handle_2fa()
            
            # Verify success
            success = await self._verify_login_success()
            
            if success:
                self.authenticated = True
                await self._save_session()
                logger.info("[2FA] Login successful")
            else:
                logger.warning("[2FA] Login may have failed")
            
            return success
            
        except Exception as e:
            logger.error(f"[2FA] Login failed: {str(e)}")
            return False
    
    async def _execute_login_step(self, step: str):
        """Execute a single login flow step"""
        step_lower = step.lower()
        
        # Parse step instruction
        if 'type' in step_lower:
            # Type into a field
            if '$username' in step:
                value = self.auth_config.credentials.get('username', '')
            elif '$password' in step:
                value = self.auth_config.credentials.get('password', '')
            else:
                # Extract value from instruction
                value = ''
            
            # Find the field
            field_desc = step.split('into')[-1].strip() if 'into' in step_lower else ''
            selector = await self._find_field_selector(field_desc)
            
            if selector:
                await self.page.fill(selector, value)
                
        elif 'click' in step_lower:
            # Click a button/link
            button_desc = step.split('click')[-1].strip() if 'click' in step_lower else ''
            selector = await self._find_button_selector(button_desc)
            
            if selector:
                await self.page.click(selector)
                await self.page.wait_for_load_state('networkidle')
    
    async def _find_field_selector(self, description: str) -> Optional[str]:
        """Find a form field selector based on description"""
        # Common input field selectors
        selectors = [
            f'input[name*="{description}"]',
            f'input[placeholder*="{description}"]',
            f'input[id*="{description}"]',
            f'input[aria-label*="{description}"]',
        ]
        
        for selector in selectors:
            try:
                element = await self.page.query_selector(selector)
                if element:
                    return selector
            except:
                continue
        
        # Use LLM for intelligent detection if available
        if self.llm:
            page_content = await self.page.content()
            prompt = f"""
            Find the CSS selector for the form field described as: "{description}"
            
            Page HTML (truncated):
            {page_content[:3000]}
            
            Return ONLY the CSS selector, nothing else.
            """
            try:
                selector = self.llm.output(prompt).strip()
                if selector:
                    return selector
            except:
                pass
        
        return None
    
    async def _find_button_selector(self, description: str) -> Optional[str]:
        """Find a button selector based on description"""
        selectors = [
            f'button:has-text("{description}")',
            f'input[type="submit"][value*="{description}"]',
            f'a:has-text("{description}")',
        ]
        
        for selector in selectors:
            try:
                element = await self.page.query_selector(selector)
                if element:
                    return selector
            except:
                continue
        
        return None
    
    async def _detect_2fa_prompt(self) -> bool:
        """Detect if 2FA prompt is shown"""
        # Common 2FA indicators
        indicators = [
            'input[name*="totp"]',
            'input[name*="otp"]',
            'input[name*="code"]',
            'input[name*="2fa"]',
            'input[placeholder*="code"]',
            'input[placeholder*="authenticator"]',
        ]
        
        for selector in indicators:
            try:
                element = await self.page.query_selector(selector)
                if element:
                    return True
            except:
                continue
        
        # Check page text for 2FA keywords
        page_text = await self.page.inner_text('body')
        keywords = [
            'two-factor', 'two factor', '2fa', 'authenticator',
            'verification code', 'security code', 'one-time password'
        ]
        
        for keyword in keywords:
            if keyword in page_text.lower():
                return True
        
        return False
    
    async def _handle_2fa(self):
        """Handle 2FA code entry"""
        # Generate TOTP code
        code = self.generate_totp_code()
        if not code:
            logger.error("[2FA] Could not generate TOTP code")
            return
        
        # Wait for code to be valid (avoid edge cases)
        remaining = get_remaining_seconds()
        if remaining < 5:
            logger.info(f"[2FA] Waiting {remaining + 1}s for new code")
            await self.page.wait_for_timeout((remaining + 1) * 1000)
            code = self.generate_totp_code()
        
        # Find 2FA input field
        selectors = [
            'input[name*="totp"]',
            'input[name*="otp"]',
            'input[name*="code"]',
            'input[name*="2fa"]',
            'input[type="tel"]',
            'input[inputmode="numeric"]',
        ]
        
        for selector in selectors:
            try:
                element = await self.page.query_selector(selector)
                if element:
                    await self.page.fill(selector, code)
                    logger.info(f"[2FA] Entered TOTP code in {selector}")
                    
                    # Submit the code
                    await self.page.keyboard.press('Enter')
                    await self.page.wait_for_load_state('networkidle')
                    return
            except:
                continue
        
        logger.warning("[2FA] Could not find 2FA input field")
    
    async def _verify_login_success(self) -> bool:
        """Verify that login was successful"""
        if not self.auth_config.success_condition:
            # Default: check that we're not on login page
            current_url = self.page.url
            return 'login' not in current_url.lower()
        
        condition_type = self.auth_config.success_condition.get('type')
        condition_value = self.auth_config.success_condition.get('value')
        
        if condition_type == 'url_contains':
            return condition_value in self.page.url
        
        elif condition_type == 'url_not_contains':
            return condition_value not in self.page.url
        
        elif condition_type == 'element_exists':
            element = await self.page.query_selector(condition_value)
            return element is not None
        
        elif condition_type == 'element_not_exists':
            element = await self.page.query_selector(condition_value)
            return element is None
        
        return False
    
    async def _save_session(self):
        """Save session data for reuse"""
        try:
            # Get cookies
            cookies = await self.page.context.cookies()
            self.session_data['cookies'] = cookies
            
            # Get storage
            storage = await self.page.context.storage_state()
            self.session_data['storage_state'] = storage
            
            logger.info("[2FA] Session data saved")
        except Exception as e:
            logger.error(f"[2FA] Failed to save session: {str(e)}")
    
    async def restore_session(self) -> bool:
        """Restore saved session data"""
        if not self.session_data.get('cookies'):
            return False
        
        try:
            await self.page.context.add_cookies(self.session_data['cookies'])
            self.authenticated = True
            logger.info("[2FA] Session restored")
            return True
        except Exception as e:
            logger.error(f"[2FA] Failed to restore session: {str(e)}")
            return False


def load_auth_config(config_path: str) -> AuthConfig:
    """
    Load authentication configuration from YAML file.
    
    Parameters:
        config_path: Path to YAML configuration file
        
    Returns:
        AuthConfig object
    """
    import yaml
    
    with open(config_path, 'r') as f:
        data = yaml.safe_load(f)
    
    auth_data = data.get('authentication', {})
    
    return AuthConfig(
        login_type=auth_data.get('login_type', 'form'),
        login_url=auth_data.get('login_url', ''),
        credentials=auth_data.get('credentials', {}),
        totp_secret=auth_data.get('credentials', {}).get('totp_secret'),
        login_flow=auth_data.get('login_flow', []),
        success_condition=auth_data.get('success_condition', {})
    )
