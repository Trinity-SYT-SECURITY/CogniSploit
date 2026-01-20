"""
AI Service Fingerprinter
Identifies AI service providers
"""
import re
import json
from typing import Dict, List, Optional


class AIServiceFingerprinter:
    """AI service fingerprinting"""
    
    def __init__(self):
        self.fingerprints = {
            'openai': {
                'api_patterns': [
                    r'/v1/chat/completions',
                    r'/v1/completions',
                    r'/v1/models'
                ],
                'error_patterns': [
                    r'"error".*"type".*"invalid_request_error"',
                    r'"error".*"message".*"You exceeded your current quota"',
                    r'rate_limit_exceeded'
                ],
                'response_structure': {
                    'has_choices': True,
                    'has_usage': True,
                    'has_model': True
                },
                'headers': {
                    'authorization': r'Bearer sk-',
                    'content-type': 'application/json'
                }
            },
            'anthropic': {
                'api_patterns': [
                    r'/v1/messages',
                    r'/v1/complete'
                ],
                'error_patterns': [
                    r'"error".*"type".*"invalid_request_error"',
                    r'"error".*"message".*"rate_limit_error"'
                ],
                'response_structure': {
                    'has_content': True,
                    'has_stop_reason': True
                },
                'headers': {
                    'x-api-key': r'anthropic-',
                    'anthropic-version': True
                }
            },
            'google': {
                'api_patterns': [
                    r'/v1beta/models',
                    r'/v1/models.*:generateContent',
                    r'/v1/models.*:chat'
                ],
                'error_patterns': [
                    r'"error".*"code".*"INVALID_ARGUMENT"',
                    r'"error".*"status".*"PERMISSION_DENIED"'
                ],
                'response_structure': {
                    'has_candidates': True,
                    'has_prompt_feedback': True
                },
                'headers': {
                    'x-goog-api-key': True
                }
            }
        }
    
    def identify_provider(self, api_response: Dict = None, 
                         network_traffic: List[Dict] = None,
                         url: str = None) -> Optional[str]:
        """
        Identify AI service provider
        
        Parameters:
            api_response: API response content
            network_traffic: Network traffic
            url: API endpoint URL
            
        Returns:
            Provider name or None
        """
        scores = {}
        
        # Check URL patterns
        if url:
            for provider, fingerprint in self.fingerprints.items():
                for pattern in fingerprint['api_patterns']:
                    if re.search(pattern, url, re.IGNORECASE):
                        scores[provider] = scores.get(provider, 0) + 10
        
        # Check response structure
        if api_response:
            response_str = json.dumps(api_response) if isinstance(api_response, dict) else str(api_response)
            
            for provider, fingerprint in self.fingerprints.items():
                # Check response structure
                structure = fingerprint.get('response_structure', {})
                for key, expected in structure.items():
                    if expected is True and key in response_str.lower():
                        scores[provider] = scores.get(provider, 0) + 5
                
                # Check error patterns
                error_patterns = fingerprint.get('error_patterns', [])
                for pattern in error_patterns:
                    if re.search(pattern, response_str, re.IGNORECASE):
                        scores[provider] = scores.get(provider, 0) + 3
        
        # Check network traffic
        if network_traffic:
            for request in network_traffic:
                headers = request.get('headers', {})
                url_req = request.get('url', '')
                
                for provider, fingerprint in self.fingerprints.items():
                    # Check headers
                    header_patterns = fingerprint.get('headers', {})
                    for header_name, pattern in header_patterns.items():
                        header_value = headers.get(header_name, '').lower()
                        if pattern is True and header_value:
                            scores[provider] = scores.get(provider, 0) + 5
                        elif isinstance(pattern, str) and re.search(pattern, header_value, re.IGNORECASE):
                            scores[provider] = scores.get(provider, 0) + 5
                    
                    # Check URL
                    for api_pattern in fingerprint.get('api_patterns', []):
                        if re.search(api_pattern, url_req, re.IGNORECASE):
                            scores[provider] = scores.get(provider, 0) + 10
        
        # Return provider with highest score
        if scores:
            return max(scores.items(), key=lambda x: x[1])[0]
        
        return None
    
    def get_provider_info(self, provider: str) -> Dict:
        """Get provider information"""
        return self.fingerprints.get(provider, {})

