import os
import re
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
import random

logger = logging.getLogger(__name__)

class WordlistManager:
    """
    Manages wordlists and provides intelligent selection of payloads and entries
    based on context and attack type.
    """
    
    def __init__(self, project_root: str = None, wordlists_dir: str = 'lists'):
        self.project_root = project_root or os.getcwd()
        self.lists_dir = os.path.join(self.project_root, wordlists_dir)
        self.wordlist_cache = {}
        self.wordlist_metadata = {}
        self._load_wordlist_metadata()
        
    def _load_wordlist_metadata(self):
        """Load metadata about available wordlists."""
        try:
            if os.path.exists(self.lists_dir):
                for file_path in Path(self.lists_dir).glob("*.txt"):
                    file_name = file_path.name
                    file_size = file_path.stat().st_size
                    line_count = self._count_lines(file_path)
                    
                    self.wordlist_metadata[file_name] = {
                        "path": str(file_path),
                        "size": file_size,
                        "line_count": line_count,
                        "type": self._categorize_wordlist(file_name),
                        "description": self._get_wordlist_description(file_name)
                    }
        except Exception as e:
            logger.error(f"[WordlistManager] Error loading wordlist metadata: {str(e)}")
    
    def _count_lines(self, file_path: Path) -> int:
        """Count lines in a file efficiently."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except Exception:
            return 0
    
    def _categorize_wordlist(self, filename: str) -> str:
        """Categorize wordlist based on filename."""
        filename_lower = filename.lower()
        
        if any(word in filename_lower for word in ["sql", "injection", "sqli"]):
            return "sql_injection"
        elif any(word in filename_lower for word in ["xss", "script", "javascript"]):
            return "xss"
        elif any(word in filename_lower for word in ["password", "pass", "pwd"]):
            return "authentication"
        elif any(word in filename_lower for word in ["subdomain", "sub"]):
            return "subdomain"
        elif any(word in filename_lower for word in ["directory", "dir", "fuzz"]):
            return "directory"
        elif any(word in filename_lower for word in ["username", "user", "login"]):
            return "authentication"
        elif any(word in filename_lower for word in ["lfi", "rfi", "file"]):
            return "file_inclusion"
        elif any(word in filename_lower for word in ["command", "cmd", "exec"]):
            return "command_injection"
        elif any(word in filename_lower for word in ["no-sql", "nosql", "mongo"]):
            return "nosql_injection"
        elif any(word in filename_lower for word in ["oracle", "mssql", "mysql", "postgres"]):
            return "database_specific"
        else:
            return "generic"
    
    def _get_wordlist_description(self, filename: str) -> str:
        """Get human-readable description of wordlist."""
        filename_lower = filename.lower()
        
        descriptions = {
            "sql_injection": "SQL injection payloads and techniques",
            "xss": "Cross-site scripting payloads",
            "authentication": "Username and password combinations",
            "subdomain": "Common subdomain names",
            "directory": "Common directory and file paths",
            "file_inclusion": "Local and remote file inclusion payloads",
            "command_injection": "Command injection payloads",
            "nosql_injection": "NoSQL injection techniques",
            "database_specific": "Database-specific injection payloads",
            "generic": "General purpose payloads"
        }
        
        category = self._categorize_wordlist(filename)
        return descriptions.get(category, "General purpose wordlist")
    
    def get_available_wordlists(self) -> List[Dict[str, str]]:
        """Get list of available wordlists with metadata."""
        return [
            {
                "filename": filename,
                **metadata
            }
            for filename, metadata in self.wordlist_metadata.items()
        ]
    
    def get_wordlist_by_type(self, wordlist_type: str) -> List[str]:
        """Get wordlists of a specific type."""
        matching_wordlists = []
        for filename, metadata in self.wordlist_metadata.items():
            if metadata["type"] == wordlist_type:
                matching_wordlists.append(filename)
        return matching_wordlists
    
    def suggest_wordlists_for_context(self, context: str) -> List[str]:
        """
        Suggest appropriate wordlists based on context.
        
        Parameters:
            context: Context description or attack type
            
        Returns:
            List of suggested wordlist filenames
        """
        context_lower = context.lower()
        suggestions = []
        
        # SQL Injection context
        if any(word in context_lower for word in ["sql", "database", "injection", "sqli"]):
            suggestions.extend(self.get_wordlist_by_type("sql_injection"))
            suggestions.extend(self.get_wordlist_by_type("database_specific"))
        
        # XSS context
        if any(word in context_lower for word in ["xss", "script", "javascript", "reflected"]):
            suggestions.extend(self.get_wordlist_by_type("xss"))
        
        # Authentication context
        if any(word in context_lower for word in ["login", "password", "brute force", "auth", "credential"]):
            suggestions.extend(self.get_wordlist_by_type("authentication"))
        
        # Directory enumeration context
        if any(word in context_lower for word in ["directory", "path", "hidden", "enumeration", "discovery"]):
            suggestions.extend(self.get_wordlist_by_type("directory"))
        
        # Subdomain context
        if any(word in context_lower for word in ["subdomain", "dns", "enumeration"]):
            suggestions.extend(self.get_wordlist_by_type("subdomain"))
        
        # File inclusion context
        if any(word in context_lower for word in ["lfi", "rfi", "file inclusion", "path traversal"]):
            suggestions.extend(self.get_wordlist_by_type("file_inclusion"))
        
        # Command injection context
        if any(word in context_lower for word in ["command", "exec", "cmd", "shell"]):
            suggestions.extend(self.get_wordlist_by_type("command_injection"))
        
        # NoSQL context
        if any(word in context_lower for word in ["nosql", "mongo", "json"]):
            suggestions.extend(self.get_wordlist_by_type("nosql_injection"))
        
        # Remove duplicates and return
        return list(set(suggestions))
    
    def load_wordlist_content(self, filename: str, max_lines: int = None) -> List[str]:
        """
        Load content from a wordlist file.
        
        Parameters:
            filename: Name of the wordlist file
            max_lines: Maximum number of lines to load (None for all)
            
        Returns:
            List of wordlist entries
        """
        if filename in self.wordlist_cache:
            content = self.wordlist_cache[filename]
            if max_lines:
                return content[:max_lines]
            return content
        
        file_path = os.path.join(self.lists_dir, filename)
        if not os.path.exists(file_path):
            logger.warning(f"[WordlistManager] Wordlist file not found: {filename}")
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
                # Cache the content
                self.wordlist_cache[filename] = content
                
                if max_lines:
                    return content[:max_lines]
                return content
                
        except Exception as e:
            logger.error(f"[WordlistManager] Error loading wordlist {filename}: {str(e)}")
            return []
    
    def get_smart_payloads(self, context: str, attack_type: str, count: int = 10) -> List[str]:
        """
        Get smart payloads based on context and attack type.
        
        Parameters:
            context: Context description
            attack_type: Type of attack being performed
            count: Number of payloads to return
            
        Returns:
            List of selected payloads
        """
        # Suggest appropriate wordlists
        suggested_wordlists = self.suggest_wordlists_for_context(context)
        
        if not suggested_wordlists:
            # Fallback to generic wordlists
            suggested_wordlists = [filename for filename, metadata in self.wordlist_metadata.items() 
                                 if metadata["type"] == "generic"]
        
        if not suggested_wordlists:
            return []
        
        # Load content from suggested wordlists
        all_payloads = []
        for wordlist in suggested_wordlists:
            payloads = self.load_wordlist_content(wordlist)
            all_payloads.extend(payloads)
        
        # Remove duplicates and filter by relevance
        unique_payloads = list(set(all_payloads))
        relevant_payloads = self._filter_payloads_by_relevance(unique_payloads, attack_type)
        
        # Select payloads based on count
        if len(relevant_payloads) <= count:
            return relevant_payloads
        
        # Smart selection: mix of different payload types
        selected_payloads = []
        
        # Add some basic payloads
        basic_payloads = [p for p in relevant_payloads if len(p) < 50]
        if basic_payloads:
            selected_payloads.extend(random.sample(basic_payloads, min(count // 3, len(basic_payloads))))
        
        # Add some advanced payloads
        advanced_payloads = [p for p in relevant_payloads if len(p) >= 50]
        if advanced_payloads:
            selected_payloads.extend(random.sample(advanced_payloads, min(count // 3, len(advanced_payloads))))
        
        # Fill remaining with random payloads
        remaining_count = count - len(selected_payloads)
        if remaining_count > 0:
            remaining_payloads = [p for p in relevant_payloads if p not in selected_payloads]
            if remaining_payloads:
                selected_payloads.extend(random.sample(remaining_payloads, min(remaining_count, len(remaining_payloads))))
        
        return selected_payloads[:count]
    
    def _filter_payloads_by_relevance(self, payloads: List[str], attack_type: str) -> List[str]:
        """Filter payloads by relevance to attack type."""
        if not attack_type:
            return payloads
        
        attack_type_lower = attack_type.lower()
        relevant_payloads = []
        
        for payload in payloads:
            payload_lower = payload.lower()
            
            # SQL Injection relevance
            if "sql" in attack_type_lower or "injection" in attack_type_lower:
                if any(word in payload_lower for word in ["'", "union", "select", "drop", "insert", "update", "delete"]):
                    relevant_payloads.append(payload)
            
            # XSS relevance
            elif "xss" in attack_type_lower or "script" in attack_type_lower:
                if any(word in payload_lower for word in ["<script", "javascript:", "onerror", "onload", "alert("]):
                    relevant_payloads.append(payload)
            
            # Command injection relevance
            elif "command" in attack_type_lower or "exec" in attack_type_lower:
                if any(word in payload_lower for word in [";", "|", "&", "`", "$(", "eval("]):
                    relevant_payloads.append(payload)
            
            # File inclusion relevance
            elif "file" in attack_type_lower or "lfi" in attack_type_lower or "rfi" in attack_type_lower:
                if any(word in payload_lower for word in ["../", "..\\", "file://", "http://", "ftp://"]):
                    relevant_payloads.append(payload)
            
            # Authentication relevance
            elif "auth" in attack_type_lower or "login" in attack_type_lower:
                if any(word in payload_lower for word in ["admin", "root", "user", "password", "123", "test"]):
                    relevant_payloads.append(payload)
            
            # Generic relevance for other types
            else:
                relevant_payloads.append(payload)
        
        return relevant_payloads if relevant_payloads else payloads
    
    def get_wordlist_stats(self) -> Dict[str, int]:
        """Get statistics about available wordlists."""
        stats = {
            "total_wordlists": len(self.wordlist_metadata),
            "total_entries": sum(metadata["line_count"] for metadata in self.wordlist_metadata.values()),
            "total_size_mb": sum(metadata["size"] for metadata in self.wordlist_metadata.values()) / (1024 * 1024)
        }
        
        # Count by type
        type_counts = {}
        for metadata in self.wordlist_metadata.values():
            wordlist_type = metadata["type"]
            type_counts[wordlist_type] = type_counts.get(wordlist_type, 0) + 1
        
        stats["by_type"] = type_counts
        return stats
    
    def search_wordlists(self, query: str) -> List[Dict[str, str]]:
        """
        Search wordlists for specific content.
        
        Parameters:
            query: Search query
            
        Returns:
            List of matching wordlist entries with metadata
        """
        results = []
        query_lower = query.lower()
        
        for filename, metadata in self.wordlist_metadata.items():
            # Search in filename
            if query_lower in filename.lower():
                results.append({
                    "filename": filename,
                    "match_type": "filename",
                    "metadata": metadata
                })
                continue
            
            # Search in content
            try:
                content = self.load_wordlist_content(filename)
                matching_lines = [line for line in content if query_lower in line.lower()]
                
                if matching_lines:
                    results.append({
                        "filename": filename,
                        "match_type": "content",
                        "match_count": len(matching_lines),
                        "sample_matches": matching_lines[:5],
                        "metadata": metadata
                    })
            except Exception as e:
                logger.debug(f"[WordlistManager] Error searching {filename}: {str(e)}")
        
        return results
    
    def get_contextual_suggestions(self, ai_output: str) -> str:
        """
        Get contextual suggestions for wordlist usage based on AI output.
        
        Parameters:
            ai_output: AI output text
            
        Returns:
            Formatted suggestions string
        """
        suggestions = []
        ai_output_lower = ai_output.lower()
        
        # Analyze AI output for context
        if any(word in ai_output_lower for word in ["sql", "injection", "database"]):
            suggestions.append("* SQL INJECTION CONTEXT DETECTED")
            sql_wordlists = self.get_wordlist_by_type("sql_injection")
            if sql_wordlists:
                suggestions.append(f"  Recommended wordlists: {', '.join(sql_wordlists)}")
                sample_payloads = self.get_smart_payloads("SQL injection testing", "sql_injection", 3)
                if sample_payloads:
                    suggestions.append(f"  Sample payloads: {', '.join(sample_payloads)}")
        
        if any(word in ai_output_lower for word in ["xss", "script", "javascript"]):
            suggestions.append("* CROSS-SITE SCRIPTING CONTEXT DETECTED")
            xss_wordlists = self.get_wordlist_by_type("xss")
            if xss_wordlists:
                suggestions.append(f"  Recommended wordlists: {', '.join(xss_wordlists)}")
                sample_payloads = self.get_smart_payloads("XSS testing", "xss", 3)
                if sample_payloads:
                    suggestions.append(f"  Sample payloads: {', '.join(sample_payloads)}")
        
        if any(word in ai_output_lower for word in ["directory", "path", "hidden", "enumeration"]):
            suggestions.append("* DIRECTORY ENUMERATION CONTEXT DETECTED")
            dir_wordlists = self.get_wordlist_by_type("directory")
            if dir_wordlists:
                suggestions.append(f"  Recommended wordlists: {', '.join(dir_wordlists)}")
        
        if any(word in ai_output_lower for word in ["subdomain", "dns", "enumeration"]):
            suggestions.append("* SUBDOMAIN ENUMERATION CONTEXT DETECTED")
            sub_wordlists = self.get_wordlist_by_type("subdomain")
            if sub_wordlists:
                suggestions.append(f"  Recommended wordlists: {', '.join(sub_wordlists)}")
        
        if any(word in ai_output_lower for word in ["password", "brute force", "login", "credential"]):
            suggestions.append("* AUTHENTICATION TESTING CONTEXT DETECTED")
            auth_wordlists = self.get_wordlist_by_type("authentication")
            if auth_wordlists:
                suggestions.append(f"  Recommended wordlists: {', '.join(auth_wordlists)}")
        
        if not suggestions:
            suggestions.append("* GENERAL CONTEXT")
            stats = self.get_wordlist_stats()
            suggestions.append(f"  Available wordlists: {stats['total_wordlists']}")
            suggestions.append(f"  Total entries: {stats['total_entries']:,}")
            suggestions.append(f"  Total size: {stats['total_size_mb']:.2f} MB")
        
        return "\n".join(suggestions)
    
    def cleanup(self):
        """Clean up resources."""
        self.wordlist_cache.clear()
        self.wordlist_metadata.clear()
