import os
import requests
import pathlib
import time
import base64
from urllib.parse import urlparse
import tiktoken

# ANSI color codes for logging
COLORS = {
    'white': '\033[97m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'red': '\033[91m',
    'cyan': '\033[96m',
    'light_cyan': '\033[94m',
    'light_magenta': '\033[95m',
    'dark_gray': '\033[90m',
    'reset': '\033[0m'
}


def check_hostname(url_start: str, url_to_check: str) -> bool:
   
    # Extract the netloc from both URLs
    start_netloc = urlparse(url_start).netloc
    check_netloc = urlparse(url_to_check).netloc

    # Handle empty or malformed netloc
    if not start_netloc or not check_netloc:
        return False

    # Function to extract the root domain from a netloc
    def extract_root_domain(netloc: str) -> str:
        # Split the netloc into parts (e.g., "wwwuat.arraynetworks.com" -> ["wwwuat", "arraynetworks", "com"])
        parts = netloc.split('.')

        # Handle special cases like "co.uk" or "com.au" (public suffixes)
        # For simplicity, assume the last two parts are the root domain (e.g., "arraynetworks.com")
        # In a production environment, use a library like `tldextract` for accurate public suffix handling
        if len(parts) >= 2:
            # Take the last two parts as the root domain (e.g., "arraynetworks.com")
            return '.'.join(parts[-2:])
        return netloc  # Fallback for single-part netloc (e.g., "localhost")

    # Extract the root domain for both URLs
    start_root_domain = extract_root_domain(start_netloc)  # e.g., "arraynetworks.com"
    check_root_domain = extract_root_domain(check_netloc)  # e.g., "arraynetworks.com"

    # Check if the netloc of url_to_check ends with the root domain of url_start
    # This ensures subdomains are included (e.g., "www.arraynetworks.com" ends with "arraynetworks.com")
    return check_netloc.endswith(start_root_domain) and start_root_domain == check_root_domain

def enumerate_subdomains(url: str) -> list:
    """
    Find valid subdomains for a given domain by testing common subdomain names.
    
    Parameters:
        url: Base URL to check subdomains for
        
    Returns:
        list: List of valid subdomain URLs that returned HTTP 200
    """ 
    # Extract the root domain from the URL
    parsed = urlparse(url)
    hostname = parsed.netloc
    # Remove any www. prefix if present
    if hostname.startswith('www.'):
        hostname = hostname[4:]
    # Split on dots and take last two parts to get root domain
    parts = hostname.split('.')
    if len(parts) > 2:
        hostname = '.'.join(parts[-2:])

    subdomains_path = pathlib.Path(__file__).parent / "lists" / "subdomains.txt"
    with open(subdomains_path, "r") as f:
        subdomains = f.read().splitlines()

    valid_domains = []
    for subdomain in subdomains:
        for scheme in ["https", "http"]:
            url_to_check = f"{scheme}://{subdomain}.{hostname}"
            try:
                response = requests.get(url_to_check, timeout=5)
                if response.status_code == 200:
                    print(f"[INFO] Found a valid subdomain: {url_to_check}")
                    valid_domains.append(url_to_check)
            except:
                continue

    return valid_domains

def get_base64_image(page) -> str:
    """
    Take a screenshot of the page and return it as a base64 encoded string.
    
    Parameters:
        page: Playwright page object
        
    Returns:
        str: Base64 encoded screenshot image
    """
    screenshot_path = "temp/temp_screenshot.png"
    page.screenshot(path=screenshot_path)
    with open(screenshot_path, "rb") as image_file:
        base64_image = base64.b64encode(image_file.read()).decode("utf-8")
    return base64_image

def wait_for_network_idle(page, timeout: int = 100000) -> None:
    """
    Wait for network activity to become idle.
    
    Parameters:
        page: Playwright page object
        timeout: Maximum time to wait in milliseconds (default: 4000)
    """
    try:
        page.wait_for_load_state('networkidle', timeout=timeout)
    except Exception as e:
        # If timeout occurs, give a small delay anyway
        time.sleep(1)  # Fallback delay

def count_tokens(text, model: str = "gpt-4o") -> int:
    """
    Count the number of tokens in a text string using OpenAI's tokenizer.
    
    Parameters:
        text: The text to tokenize (string or list of dicts with content key)
        model: The model to use for tokenization (default: gpt-4o)
        
    Returns:
        int: The number of tokens in the text
    """
    if isinstance(text, list):
        text = " ".join(str(item.get("content", "")) for item in text)
    
    encoder = tiktoken.encoding_for_model("gpt-4o")
    tokens = encoder.encode(text)
    return len(tokens)

def read_gemini_keys():
    """
    Read Gemini API key from .env file.
    
    Returns:
        list: List containing the API key from environment variable, or empty list if not found.
    """
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        print(f"{COLORS['yellow']}[Utils.read_gemini_keys] GEMINI_API_KEY not found in .env file.{COLORS['reset']}")
        return []
    return [api_key]

def update_env_file(env_key: str, new_key: str):
    """
    Update the specified environment variable in the .env file and set it in os.environ.
    
    Parameters:
        env_key: The environment variable name to update (e.g., 'GEMINI_API_KEY', 'OPENAI_API_KEY').
        new_key: The new API key to set.
        
    Returns:
        bool: True if update successful, False otherwise.
    """
    env_file = ".env"
    try:
        with open(env_file, "r") as f:
            lines = f.readlines()
        new_lines = []
        key_updated = False
        for line in lines:
            if line.strip().startswith(f"{env_key}="):
                new_lines.append(f"{env_key}={new_key}\n")
                key_updated = True
            else:
                new_lines.append(line)
        if not key_updated:
            new_lines.append(f"{env_key}={new_key}\n")
        with open(env_file, "w") as f:
            f.writelines(new_lines)
        print(f"{COLORS['green']}[Utils.update_env_file] Updated {env_key} in {env_file}.{COLORS['reset']}")
        os.environ[env_key] = new_key
        return True
    except Exception as e:
        print(f"{COLORS['red']}[Utils.update_env_file] Failed to update {env_file}: {str(e)}{COLORS['reset']}")
        return False