import re
import json
import logging
from typing import Dict, List, Optional, Tuple, Set
from tools.external_tool_executor import ExternalToolExecutor

# Use standard logging without color parameters
logger = logging.getLogger(__name__)

class AIToolDetector:
    """
    Detects when AI mentions external tools and automatically executes them.
    Monitors AI output for tool keywords and manages tool execution lifecycle.
    """
    
    def __init__(self, project_root: str = None, wordlists_dir: str = 'lists', target_url: str = None, 
                 db_callback=None):
        self.project_root = project_root
        self.wordlists_dir = wordlists_dir
        self.target_url = target_url
        self.db_callback = db_callback  # Callback to save results to database
        self.executor = ExternalToolExecutor(project_root, wordlists_dir)
        self.available_tools = self._load_available_tools()
        self.tool_keywords = self._build_tool_keywords()
        self.execution_history = []
        
    def _load_available_tools(self) -> List[Dict[str, str]]:
        """Load available tools from configuration."""
        try:
            return self.executor.get_available_tools()
        except Exception as e:
            logger.error(f"[AIToolDetector] Error loading tools: {str(e)}")
            return []
    
    def _build_tool_keywords(self) -> Dict[str, Set[str]]:
        """Build keyword mappings for tool detection dynamically from JSON config."""
        keywords = {}
        for tool in self.available_tools:
            tool_name = tool["tool_name"]
            tool_description = tool.get("description", "").lower()
            security_context = tool.get("security_context", "").lower()
            
            # Create dynamic keyword set based on tool name and description
            tool_keywords = {tool_name.lower()}
            
            # Extract relevant keywords from description and security context
            if tool_description:
                # Split description into words and add relevant ones
                desc_words = tool_description.split()
                for word in desc_words:
                    if len(word) > 3 and word not in ["the", "and", "for", "with", "tool", "tool"]:
                        tool_keywords.add(word.lower())
            
            if security_context:
                # Split security context into words and add relevant ones
                context_words = security_context.split()
                for word in context_words:
                    if len(word) > 3 and word not in ["the", "and", "for", "with", "tool", "tool"]:
                        tool_keywords.add(word.lower())
            
            # Add common variations based on tool name patterns
            if "scan" in tool_name.lower() or "scan" in tool_description:
                tool_keywords.update(["scan", "scanning", "scanner"])
            if "enum" in tool_name.lower() or "enum" in tool_description:
                tool_keywords.update(["enum", "enumeration", "enumerate"])
            if "injection" in tool_name.lower() or "injection" in tool_description:
                tool_keywords.update(["injection", "inject", "sqli", "xss"])
            if "brute" in tool_name.lower() or "brute" in tool_description:
                tool_keywords.update(["brute", "bruteforce", "password", "crack"])
            
            keywords[tool_name] = tool_keywords
        
        return keywords
    
    def detect_tool_mentions(self, ai_output: str) -> List[Dict[str, str]]:
        """
        Detect mentions of external tools in AI output.
        
        Parameters:         
            ai_output: The AI's output text
            
        Returns:
            List of detected tool mentions with context
        """
        detected_tools = []
        ai_output_lower = ai_output.lower()
        
        for tool_name, keywords in self.tool_keywords.items():
            for keyword in keywords:
                if keyword in ai_output_lower:
                    # Find the context around the keyword
                    context_start = max(0, ai_output_lower.find(keyword) - 100)
                    context_end = min(len(ai_output_lower), ai_output_lower.find(keyword) + 100)
                    context = ai_output_lower[context_start:context_end]
                    
                    detected_tools.append({
                        "tool_name": tool_name,
                        "keyword": keyword,
                        "context": context,
                        "full_output": ai_output
                    })
                    break  # Only add each tool once
        
        return detected_tools
    
    def extract_tool_parameters(self, tool_name: str, ai_output: str) -> Dict[str, str]:
        """
        Extract tool parameters from AI output using intelligent parsing.
        
        Parameters:
            tool_name: Name of the tool
            ai_output: AI output text
            
        Returns:
            Dictionary of extracted parameters
        """
        tool_config = next((tool for tool in self.available_tools if tool["tool_name"] == tool_name), None)
        if not tool_config:
            return {}
        
        parameters = {}
        required_params = {param["name"] for param in tool_config.get("parameters", [])}
        
        # Extract target information from AI output
        if "target" in required_params:
            # Look for URLs, IPs, or hostnames
            # Exclude backticks from URL matching to handle markdown code formatting
            url_pattern = r'https?://[^\s\'\"`]+'
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            hostname_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b'
            
            urls = re.findall(url_pattern, ai_output)
            ips = re.findall(ip_pattern, ai_output)
            hostnames = re.findall(hostname_pattern, ai_output)
            
            if urls:
                parameters["target"] = urls[0]
            elif ips:
                parameters["target"] = ips[0]
            elif hostnames:
                parameters["target"] = hostnames[0]
            elif self.target_url:
                # Use the actual target URL from Agent
                parameters["target"] = self.target_url
            else:
                # Fallback to localhost if no target found
                parameters["target"] = "http://127.0.0.1"
        
        # Extract domain information
        if "domain" in required_params:
            # First try to extract domain from target URL (most reliable)
            if self.target_url:
                from urllib.parse import urlparse
                parsed = urlparse(self.target_url)
                parameters["domain"] = parsed.netloc
            else:
                # Look for actual domain patterns (not file paths)
                domain_pattern = r'\b(?:https?://)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,}))\b'
                domains = re.findall(domain_pattern, ai_output)
                if domains:
                    # Extract the full domain from the match
                    parameters["domain"] = domains[0][0]  # First group contains full domain
                else:
                    # Fallback to localhost if no target found
                    parameters["domain"] = "127.0.0.1"
        
        # Extract wordlist information
        if "wordlist" in required_params:
            # Look for wordlist references
            wordlist_pattern = r'(?:wordlist|dictionary|list)\s*(?:file)?\s*[:\s]\s*([a-zA-Z0-9_\-\.]+)'
            wordlist_match = re.search(wordlist_pattern, ai_output, re.IGNORECASE)
            if wordlist_match:
                wordlist_name = wordlist_match.group(1)
                # Check if it exists in lists directory
                wordlist_path = f"lists/{wordlist_name}"
                if not wordlist_name.endswith('.txt'):
                    wordlist_path += '.txt'
                parameters["wordlist"] = wordlist_path
        
        # Extract port information
        if "port" in required_params:
            port_pattern = r'\b(?:port|ports?)\s*[:\s]\s*(\d+)'
            port_match = re.search(port_pattern, ai_output, re.IGNORECASE)
            if port_match:
                parameters["port"] = port_match.group(1)
        
        # Extract path information
        if "path" in required_params:
            path_pattern = r'(?:path|directory|dir)\s*[:\s]\s*([a-zA-Z0-9_\-\.\/]+)'
            path_match = re.search(path_pattern, ai_output, re.IGNORECASE)
            if path_match:
                parameters["path"] = path_match.group(1)
        
        return parameters
   
    def should_execute_tool(self, tool_name: str, ai_output: str) -> bool:
        """
        Determine if a tool should be executed based on AI output context.
        
        Parameters:
            tool_name: Name of the tool
            ai_output: AI output text
            
        Returns:
            True if tool should be executed
        """
        # Check if AI is actually requesting tool execution
        execution_indicators = [
            "use", "run", "execute", "call", "launch", "start", "perform",
            "scan with", "test with", "check with", "enumerate with",
            "brute force", "directory enumeration", "port scanning",
            "vulnerability scan", "subdomain enumeration"
        ]
        
        ai_output_lower = ai_output.lower()
        has_execution_intent = any(indicator in ai_output_lower for indicator in execution_indicators)
        
        # Check if this is just a mention vs actual request
        if not has_execution_intent:
            return False
        
        # Check if tool was mentioned in the right context
        tool_context = self._get_tool_context(tool_name)
        if tool_context:
            context_match = any(context in ai_output_lower for context in tool_context)
            return context_match
        
        return True
    
    def _get_tool_context(self, tool_name: str) -> List[str]:
        """Get relevant context keywords for a tool."""
        context_map = {
            "nmap": ["network", "port", "scan", "reconnaissance", "discovery"],
            "whatweb": ["web", "technology", "fingerprint", "detection"],
            "amass": ["subdomain", "dns", "enumeration", "discovery"],
            "gobuster": ["directory", "path", "enumeration", "discovery"],
            "nikto": ["vulnerability", "web", "security", "scan"],
            "sqlmap": ["sql", "injection", "database", "vulnerability"],
            "hydra": ["password", "brute force", "authentication", "login"]
        }
        return context_map.get(tool_name, [])
    
    def execute_detected_tools(self, ai_output: str) -> List[Dict[str, str]]:
        """
        Execute all detected tools from AI output.
        
        Parameters:
            ai_output: AI output text
            
        Returns:
            List of tool execution results
        """
        detected_tools = self.detect_tool_mentions(ai_output)
        execution_results = []
        
        for tool_info in detected_tools:
            tool_name = tool_info["tool_name"]
            
            # Check if tool should actually be executed
            if not self.should_execute_tool(tool_name, ai_output):
                continue
            
            # Extract parameters
            parameters = self.extract_tool_parameters(tool_name, ai_output)
            
            # Validate parameters
            is_valid, error_msg = self.executor.validate_tool_parameters(tool_name, parameters)
            if not is_valid:
                logger.warning(f"[AIToolDetector] Invalid parameters for {tool_name}: {error_msg}")
                execution_results.append({
                    "tool_name": tool_name,
                    "success": False,
                    "error": error_msg,
                    "parameters": parameters
                })
                continue
            
            # Execute the tool
            logger.info(f"[AIToolDetector] Executing {tool_name} with parameters: {parameters}")
            result = self.executor.execute_tool_with_wait(tool_name, parameters)
            
            # Add metadata
            result["tool_name"] = tool_name
            result["parameters"] = parameters
            result["ai_context"] = tool_info["context"]
            
            execution_results.append(result)
            
            # Store in history
            self.execution_history.append({
                "timestamp": result.get("execution_time", 0),
                "tool_name": tool_name,
                "result": result
            })
            
            # Save to database if callback is available
            if self.db_callback and callable(self.db_callback):
                try:
                    self.db_callback(
                        tool_name=tool_name,
                        target_url=self.target_url,
                        command=result.get("command", ""),
                        parameters=parameters,
                        execution_result=result
                    )
                    logger.info(f"[AIToolDetector] Saved {tool_name} results to database")
                except Exception as e:
                    logger.warning(f"[AIToolDetector] Failed to save to database: {str(e)}")
        
        return execution_results

      
    
    def get_available_tools(self) -> List[Dict[str, str]]:
        """
        Get list of available external tools.
        
        Returns:
            List of tool configurations
        """
        return self.executor.get_available_tools()
    
    def get_tool_suggestions(self, ai_output: str) -> List[str]:
        """
        Get tool suggestions based on AI output context.
        
        Parameters:
            ai_output: AI output text
            
        Returns:
            List of suggested tools
        """
        suggestions = []
        ai_output_lower = ai_output.lower()
        
        # Analyze context and suggest appropriate tools
        if any(word in ai_output_lower for word in ["port", "network", "scan"]):
            suggestions.append("nmap - for network reconnaissance and port scanning")
        
        if any(word in ai_output_lower for word in ["web", "technology", "fingerprint"]):
            suggestions.append("whatweb - for web technology detection")
        
        if any(word in ai_output_lower for word in ["subdomain", "dns", "enumeration"]):
            suggestions.append("amass - for subdomain enumeration")
        
        if any(word in ai_output_lower for word in ["directory", "path", "hidden"]):
            suggestions.append("gobuster - for directory enumeration")
        
        if any(word in ai_output_lower for word in ["vulnerability", "security", "web scan"]):
            suggestions.append("nikto - for web vulnerability scanning")
        
        if any(word in ai_output_lower for word in ["sql", "injection", "database"]):
            suggestions.append("sqlmap - for SQL injection testing")
        
        if any(word in ai_output_lower for word in ["password", "brute force", "authentication"]):
            suggestions.append("hydra - for password brute forcing")
        
        return suggestions
    
    def format_tool_results_for_ai(self, results: List[Dict[str, str]]) -> str:
        """
        Format tool execution results for AI consumption.
        
        Parameters:
            results: List of tool execution results
            
        Returns:
            Formatted string for AI
        """
        if not results:
            return ""
        
        formatted_results = []
        for result in results:
            tool_name = result["tool_name"]
            success = result.get("success", False)
            
            if success:
                output = result.get("output", "")
                execution_time = result.get("execution_time", 0)
                has_results = result.get("has_results", False)
                detailed_results = result.get("detailed_results", "")
                
                if has_results and detailed_results:
                    # Tool executed and provided detailed results
                    formatted_results.append(f"""* {tool_name.upper()} EXECUTION RESULTS
Execution time: {execution_time:.2f}s
Tool Output: {detailed_results}

AI ANALYSIS REQUIRED: Based on these {tool_name} results, analyze the findings and determine the next attack strategy. Consider:
- What vulnerabilities or weaknesses were discovered?
- What attack vectors should be pursued next?
- How should the attack strategy be adjusted based on these findings?""")
                else:
                    # Tool executed but no detailed results
                    formatted_results.append(f"* {tool_name.upper()} EXECUTION COMPLETED\nExecution time: {execution_time:.2f}s\nNote: Tool completed but no detailed results provided. Continue with current attack strategy.")
            else:
                error = result.get("error", "Unknown error")
                tool_failed = result.get("tool_failed", False)
                fallback_strategy = result.get("fallback_strategy", "")
                
                if tool_failed:
                    formatted_results.append(f"""* {tool_name.upper()} EXECUTION FAILED
Error: {error}
Fallback Strategy: {fallback_strategy}

AI DECISION REQUIRED: Since {tool_name} failed, determine alternative attack approaches:
- What internal tools can be used instead?
- What manual testing techniques should be employed?
- How should the attack strategy be modified?""")
                else:
                    formatted_results.append(f"* {tool_name.upper()} EXECUTION FAILED\nError: {error}")
        
        return "\n\n".join(formatted_results)
    
    def cleanup(self):
        """Clean up resources."""
        self.executor.cleanup_resources()
        self.execution_history.clear()
