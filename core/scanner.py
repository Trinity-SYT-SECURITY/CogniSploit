"""
Web Page Analyzer Module
Provides page content analysis for security scanning operations.
"""

import os
import requests
import json
from utils.html_parser import HTMLParser
import time
from playwright.sync_api import TimeoutError, sync_playwright

class PageAnalyzer:
    """Web page content analyzer for security scanning operations."""
    
    def __init__(self, playwright_page):
        self.page = playwright_page
        self.parser = HTMLParser()

    def scan(self, url_to_scan: str, tools=None) -> dict:
        """Navigate to target URL and extract page structure.
        
        Parameters:
            url_to_scan: Target endpoint for analysis
            tools: Optional executor for authentication flows
        
        Returns:
            Analysis result containing parsed_data, url, and html_content
        """
        # Retry mechanism for page navigation
        max_retries = 3
        retry_delay = 5  # seconds
        extended_timeout = 60000  # 60 seconds timeout

        page_source = ""
        parsed_data = {}

        for attempt in range(max_retries):
            try:
                print(f"[Scanner] Attempting to navigate to {url_to_scan} (Attempt {attempt + 1}/{max_retries})")
                self.page.goto(url_to_scan, timeout=extended_timeout, wait_until="domcontentloaded")
                print(f"[Scanner] Successfully navigated to {url_to_scan}")
                break  # Success, exit retry loop
            except TimeoutError as e:
                if attempt < max_retries - 1:
                    print(f"[Scanner] TimeoutError on attempt {attempt + 1}/{max_retries}: {str(e)}. Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    continue
                else:
                    print(f"[Scanner] Failed to navigate to {url_to_scan} after {max_retries} attempts: {str(e)}")
                    page_source = self.page.content() if self.page else ""
                    parsed_data = self.parser.parse(page_source, url_to_scan) if page_source else {}
                    return {
                        "parsed_data": parsed_data,
                        "url": url_to_scan,
                        "html_content": page_source
                    }
            except Exception as e:
                print(f"[Scanner] Unexpected error while navigating to {url_to_scan}: {str(e)}")
                page_source = self.page.content() if self.page else ""
                parsed_data = self.parser.parse(page_source, url_to_scan) if page_source else {}
                return {
                    "parsed_data": parsed_data,
                    "url": url_to_scan,
                    "html_content": page_source
                }

        # Wait for the page to stabilize
        try:
            self.page.wait_for_load_state("networkidle", timeout=extended_timeout)
            print(f"[Scanner] Page reached networkidle state for {url_to_scan}")
        except TimeoutError as e:
            print(f"[Scanner] Timeout waiting for networkidle state: {str(e)}. Proceeding with available content.")
        except Exception as e:
            print(f"[Scanner] Error waiting for networkidle state: {str(e)}. Proceeding with available content.")

        # Get the page source
        page_source = self.page.content()

        # Check for authentication requirements if tools are provided
        if tools:
            lower_html = page_source.lower()
            login_keywords = ["sign in", "log in", "username", "user id", "password", "login-form", "forgot password"]
            if any(keyword in lower_html for keyword in login_keywords):
                tools.auth_needed()
            page_source = self.page.content()  # Refresh page source after potential auth interaction

        # Parse the page source
        parsed_data = self.parser.parse(page_source, url_to_scan)

        return {
            "parsed_data": parsed_data,
            "url": url_to_scan,
            "html_content": page_source
        }