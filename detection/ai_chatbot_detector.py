"""
AI Chatbot Detector
Automatically detects AI Chatbots in web applications
"""
import re
import json
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin


class AIChatbotDetector:
    """Detects AI Chatbots in web applications"""
    
    def __init__(self):
        self.chatbot_indicators = {
            'ui_indicators': [
                r'chat.*bot|chat.*assistant|ai.*chat',
                r'send.*message|type.*message',
                r'chat.*window|chat.*interface',
                r'conversation|message.*input',
                r'ai.*assistant|virtual.*assistant'
            ],
            'api_indicators': [
                r'/api/chat|/chat|/ai|/assistant',
                r'/v1/chat/completions',  # OpenAI format
                r'/v1/completions',
                r'/v1/messages',  # Anthropic format
                r'/v1beta/models.*:generateContent',  # Google format
                r'/v1/generate',  # Generic format
                r'/api/v1/chat',
                r'/chat/completion',
                r'/ai/query'
            ],
            'js_indicators': [
                r'openai|anthropic|claude|gpt|gemini',
                r'chatgpt|chat.*completion',
                r'vector.*database|embedding|rag',
                r'langchain|llama|palm',
                r'ai.*model|language.*model'
            ],
            'class_indicators': [
                r'chat.*widget|chat.*container|chat.*box',
                r'message.*input|message.*box',
                r'ai.*chat|assistant.*chat'
            ]
        }
        
        self.provider_patterns = {
            'openai': [
                r'openai|gpt-|chatgpt',
                r'/v1/chat/completions',
                r'text-davinci|text-curie|gpt-3|gpt-4'
            ],
            'anthropic': [
                r'anthropic|claude',
                r'/v1/messages',
                r'claude-3|claude-2'
            ],
            'google': [
                r'google.*ai|gemini|palm',
                r'/v1beta/models',
                r'gemini-pro|gemini-flash|palm-2'
            ],
            'custom': [
                r'local.*model|self-hosted',
                r'/api/chat|/chat/completion'
            ]
        }
    
    def detect_in_page(self, html_content: str, network_traffic: List[Dict] = None, 
                      current_url: str = None) -> List[Dict]:
        """
        Detect AI Chatbots in page and network traffic
        
        Parameters:
            html_content: HTML page content
            network_traffic: Network traffic list (optional)
            current_url: Current page URL (optional)
            
        Returns:
            List of detected Chatbot information
        """
        detected_chatbots = []
        
        # 1. Detect UI elements
        ui_matches = self._detect_ui_elements(html_content)
        
        # 2. Detect API endpoints
        api_matches = []
        if network_traffic:
            api_matches = self._detect_api_endpoints(network_traffic, current_url)
        else:
            # Extract possible API endpoints from HTML
            api_matches = self._extract_api_endpoints_from_html(html_content, current_url)
        
        # 3. Detect JavaScript calls
        js_matches = self._detect_js_calls(html_content)
        
        # Merge results and analyze
        all_matches = ui_matches + api_matches + js_matches
        
        # Deduplicate and merge
        unique_chatbots = self._merge_detections(all_matches, current_url)
        
        return unique_chatbots
    
    def _detect_ui_elements(self, html: str) -> List[Dict]:
        """Detect chat interface UI elements"""
        matches = []
        
        # Find chat-related elements
        chat_patterns = [
            (r'<div[^>]*class="[^"]*chat[^"]*"', 'chat_container'),
            (r'<div[^>]*id="[^"]*chat[^"]*"', 'chat_container'),
            (r'<textarea[^>]*placeholder="[^"]*message[^"]*"', 'message_input'),
            (r'<input[^>]*type="[^"]*"[^>]*chat', 'chat_input'),
            (r'chat.*widget|chat.*container', 'chat_widget'),
            (r'<button[^>]*class="[^"]*send[^"]*"', 'send_button'),
            (r'message.*input|message.*box', 'message_box')
        ]
        
        for pattern, element_type in chat_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                matches.append({
                    'type': 'ui_element',
                    'element_type': element_type,
                    'pattern': pattern,
                    'confidence': 0.7
                })
        
        return matches
    
    def _detect_api_endpoints(self, traffic: List[Dict], base_url: str = None) -> List[Dict]:
        """Detect AI API endpoints from network traffic"""
        matches = []
        
        for request in traffic:
            url = request.get('url', '')
            method = request.get('method', 'GET').upper()
            
            # Only check POST requests (AI APIs are usually POST)
            if method != 'POST':
                continue
            
            # Detect OpenAI format
            if '/v1/chat/completions' in url or '/v1/completions' in url:
                matches.append({
                    'type': 'api_endpoint',
                    'url': url,
                    'provider': 'openai',
                    'confidence': 0.95,
                    'method': method
                })
            
            # Detect Anthropic format
            elif '/v1/messages' in url:
                matches.append({
                    'type': 'api_endpoint',
                    'url': url,
                    'provider': 'anthropic',
                    'confidence': 0.95,
                    'method': method
                })
            
            # Detect Google format
            elif '/v1beta/models' in url and 'generateContent' in url:
                matches.append({
                    'type': 'api_endpoint',
                    'url': url,
                    'provider': 'google',
                    'confidence': 0.95,
                    'method': method
                })
            
            # Detect generic chat endpoints
            elif any(indicator in url.lower() for indicator in ['/chat', '/ai', '/assistant', '/bot']):
                # Check if request body contains AI-related fields
                body = request.get('body', '')
                if isinstance(body, str):
                    body_lower = body.lower()
                else:
                    body_lower = json.dumps(body).lower() if body else ''
                
                ai_fields = ['message', 'prompt', 'query', 'input', 'messages', 'content']
                if any(field in body_lower for field in ai_fields):
                    matches.append({
                        'type': 'api_endpoint',
                        'url': url,
                        'provider': 'unknown',
                        'confidence': 0.7,
                        'method': method
                    })
        
        return matches
    
    def _extract_api_endpoints_from_html(self, html: str, base_url: str = None) -> List[Dict]:
        """Extract possible API endpoints from HTML"""
        matches = []
        
        # Find API calls in JavaScript
        api_patterns = [
            r'["\']([^"\']*(?:/api/chat|/chat|/ai|/assistant|/v1/chat)[^"\']*)["\']',
            r'fetch\(["\']([^"\']*)["\']',
            r'axios\.(?:post|get)\(["\']([^"\']*)["\']',
            r'\.post\(["\']([^"\']*)["\']',
            r'url:\s*["\']([^"\']*(?:chat|ai|assistant)[^"\']*)["\']'
        ]
        
        for pattern in api_patterns:
            found = re.findall(pattern, html, re.IGNORECASE)
            for url in found:
                # Build complete URL
                if base_url:
                    full_url = urljoin(base_url, url)
                else:
                    full_url = url
                
                matches.append({
                    'type': 'api_endpoint',
                    'url': full_url,
                    'provider': 'unknown',
                    'confidence': 0.5,
                    'method': 'POST',
                    'source': 'html_extraction'
                })
        
        return matches
    
    def _detect_js_calls(self, html: str) -> List[Dict]:
        """Detect AI service calls in JavaScript"""
        matches = []
        
        # Extract all script tag contents
        script_pattern = r'<script[^>]*>(.*?)</script>'
        scripts = re.findall(script_pattern, html, re.DOTALL | re.IGNORECASE)
        
        for script in scripts:
            # Detect OpenAI
            if re.search(r'openai|gpt-|chatgpt', script, re.IGNORECASE):
                matches.append({
                    'type': 'js_call',
                    'provider': 'openai',
                    'confidence': 0.8,
                    'evidence': 'OpenAI API detected in JavaScript'
                })
            
            # Detect Anthropic
            if re.search(r'anthropic|claude', script, re.IGNORECASE):
                matches.append({
                    'type': 'js_call',
                    'provider': 'anthropic',
                    'confidence': 0.8,
                    'evidence': 'Anthropic API detected in JavaScript'
                })
            
            # Detect Google
            if re.search(r'google.*ai|gemini|palm', script, re.IGNORECASE):
                matches.append({
                    'type': 'js_call',
                    'provider': 'google',
                    'confidence': 0.8,
                    'evidence': 'Google AI detected in JavaScript'
                })
            
            # Detect RAG systems
            if re.search(r'vector.*database|embedding|rag|chroma|pinecone', script, re.IGNORECASE):
                matches.append({
                    'type': 'js_call',
                    'provider': 'rag_system',
                    'confidence': 0.7,
                    'evidence': 'RAG system detected in JavaScript'
                })
        
        return matches
    
    def _merge_detections(self, matches: List[Dict], base_url: str = None) -> List[Dict]:
        """Merge and deduplicate detection results"""
        if not matches:
            return []
        
        # Group by provider
        provider_groups = {}
        
        for match in matches:
            provider = match.get('provider', 'unknown')
            if provider not in provider_groups:
                provider_groups[provider] = {
                    'provider': provider,
                    'confidence': 0,
                    'evidence': [],
                    'endpoints': [],
                    'types': set()
                }
            
            # Update confidence (take highest)
            provider_groups[provider]['confidence'] = max(
                provider_groups[provider]['confidence'],
                match.get('confidence', 0)
            )
            
            # Collect evidence
            if 'evidence' in match:
                provider_groups[provider]['evidence'].append(match['evidence'])
            
            # Collect endpoints
            if match['type'] == 'api_endpoint' and 'url' in match:
                provider_groups[provider]['endpoints'].append(match['url'])
            
            # Collect detection types
            provider_groups[provider]['types'].add(match['type'])
        
        # Convert to list
        result = []
        for provider, info in provider_groups.items():
            result.append({
                'provider': provider,
                'confidence': info['confidence'],
                'evidence': list(set(info['evidence'])),
                'endpoints': list(set(info['endpoints'])),
                'detection_types': list(info['types']),
                'base_url': base_url
            })
        
        return result
    
    def identify_chatbot_type(self, chatbot_info: Dict) -> str:
        """Identify Chatbot type"""
        provider = chatbot_info.get('provider', 'unknown')
        confidence = chatbot_info.get('confidence', 0)
        
        if confidence < 0.5:
            return 'uncertain'
        
        provider_map = {
            'openai': 'OpenAI ChatGPT',
            'anthropic': 'Anthropic Claude',
            'google': 'Google Gemini',
            'rag_system': 'RAG System',
            'custom': 'Custom LLM',
            'unknown': 'Unknown AI Service'
        }
        
        return provider_map.get(provider, 'Unknown AI Service')
    
    def is_rag_system(self, chatbot_info: Dict) -> bool:
        """Determine if it's a RAG system"""
        evidence = chatbot_info.get('evidence', [])
        evidence_str = ' '.join(evidence).lower()
        
        rag_indicators = ['rag', 'vector', 'embedding', 'retrieval', 'chroma', 'pinecone']
        return any(indicator in evidence_str for indicator in rag_indicators)

