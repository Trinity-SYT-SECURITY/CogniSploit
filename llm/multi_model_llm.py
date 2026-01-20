"""
Multi-Model LLM Collaboration System
Supports multiple LLM models working together for security testing
"""
import os
import time
import logging
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from llm.llm import LLM

logger = logging.getLogger(__name__)


class ModelRole(Enum):
    """Define roles for different models in the collaboration system"""
    SCANNER = "scanner"  # Primary model for scanning and navigation
    ANALYZER = "analyzer"  # Model for analyzing vulnerabilities
    ATTACKER = "attacker"  # Model for executing attacks
    PLANNER = "planner"  # Model for planning attack strategies
    REVIEWER = "reviewer"  # Model for reviewing and validating results
    AI_SECURITY_TESTER = "ai_security_tester"  # Model for AI chatbot security testing


class MultiModelLLM:
    """
    Multi-model LLM collaboration system for security testing.
    
    Allows multiple models to work together, each with specific roles.
    Models can collaborate by sharing context and results.
    """
    
    def __init__(self, config: Dict[str, Any] = None, debug: bool = False):
        """
        Initialize multi-model LLM system.
        
        Parameters:
            config: Configuration dictionary with model assignments
            debug: Enable debug output
        """
        self.debug = debug
        self.models: Dict[str, LLM] = {}
        self.model_roles: Dict[str, ModelRole] = {}
        self.model_configs: Dict[str, Dict[str, Any]] = {}
        self.collaboration_history: List[Dict[str, Any]] = []
        
        # Load configuration from environment or provided config
        if config is None:
            config = self._load_config_from_env()
        
        self._initialize_models(config)
        
        if self.debug:
            logger.info(f"Initialized MultiModelLLM with {len(self.models)} models")
    
    def _load_config_from_env(self) -> Dict[str, Any]:
        """Load model configuration from environment variables."""
        config = {
            "models": []
        }
        
        # Check for LiteLLM configuration
        litellm_api_base = os.getenv("LITELLM_API_BASE", "")
        litellm_api_key = os.getenv("LITELLM_API_KEY", "")
        
        if litellm_api_base and litellm_api_key:
            # Primary model (scanner)
            scanner_model = os.getenv("LITELLM_SCANNER_MODEL", os.getenv("LITELLM_MODEL", ""))
            if scanner_model:
                config["models"].append({
                    "name": "scanner",
                    "provider": "litellm",
                    "model": scanner_model,
                    "role": "scanner",
                    "api_base": litellm_api_base,
                    "api_key": litellm_api_key
                })
            
            # Analyzer model
            analyzer_model = os.getenv("LITELLM_ANALYZER_MODEL", "")
            if analyzer_model:
                config["models"].append({
                    "name": "analyzer",
                    "provider": "litellm",
                    "model": analyzer_model,
                    "role": "analyzer",
                    "api_base": litellm_api_base,
                    "api_key": litellm_api_key
                })
            
            # Attacker model
            attacker_model = os.getenv("LITELLM_ATTACKER_MODEL", "")
            if attacker_model:
                config["models"].append({
                    "name": "attacker",
                    "provider": "litellm",
                    "model": attacker_model,
                    "role": "attacker",
                    "api_base": litellm_api_base,
                    "api_key": litellm_api_key
                })
            
            # Planner model
            planner_model = os.getenv("LITELLM_PLANNER_MODEL", "")
            if planner_model:
                config["models"].append({
                    "name": "planner",
                    "provider": "litellm",
                    "model": planner_model,
                    "role": "planner",
                    "api_base": litellm_api_base,
                    "api_key": litellm_api_key
                })
            
            # Reviewer model
            reviewer_model = os.getenv("LITELLM_REVIEWER_MODEL", "")
            if reviewer_model:
                config["models"].append({
                    "name": "reviewer",
                    "provider": "litellm",
                    "model": reviewer_model,
                    "role": "reviewer",
                    "api_base": litellm_api_base,
                    "api_key": litellm_api_key
                })
            
            # AI Security Tester model
            ai_tester_model = os.getenv("LITELLM_AI_TESTER_MODEL", "")
            if ai_tester_model:
                config["models"].append({
                    "name": "ai_tester",
                    "provider": "litellm",
                    "model": ai_tester_model,
                    "role": "ai_security_tester",
                    "api_base": litellm_api_base,
                    "api_key": litellm_api_key
                })
        
        # Fallback to single model if no multi-model config
        if not config["models"]:
            # Use default single model configuration
            default_provider = os.getenv("LLM_PROVIDER", "openai")
            default_model = os.getenv("LLM_MODEL", "gpt-4o")
            
            config["models"].append({
                "name": "primary",
                "provider": default_provider,
                "model": default_model,
                "role": "scanner"
            })
        
        return config
    
    def _initialize_models(self, config: Dict[str, Any]):
        """Initialize all configured models."""
        for model_config in config.get("models", []):
            name = model_config.get("name", "primary")
            provider = model_config.get("provider", "openai")
            model_name = model_config.get("model")
            role_str = model_config.get("role", "scanner")
            
            try:
                role = ModelRole(role_str)
            except ValueError:
                logger.warning(f"Unknown role '{role_str}', defaulting to scanner")
                role = ModelRole.SCANNER
            
            # Initialize LLM instance
            if provider == "litellm":
                # Use LiteLLM provider
                # Set environment variables for LiteLLM
                if "api_base" in model_config:
                    os.environ["LITELLM_API_BASE"] = model_config["api_base"]
                if "api_key" in model_config:
                    os.environ["LITELLM_API_KEY"] = model_config["api_key"]
                llm = LLM(model_provider="litellm", model_name=model_name, debug=self.debug)
            else:
                llm = LLM(model_provider=provider, model_name=model_name, debug=self.debug)
            
            self.models[name] = llm
            self.model_roles[name] = role
            self.model_configs[name] = model_config
            
            if self.debug:
                logger.info(f"Initialized model '{name}' ({provider}/{model_name}) with role: {role.value}")
    
    def get_model_by_role(self, role: ModelRole) -> Optional[LLM]:
        """Get a model by its role."""
        for name, model_role in self.model_roles.items():
            if model_role == role:
                return self.models[name]
        return None
    
    def get_primary_model(self) -> LLM:
        """Get the primary model (scanner role)."""
        primary = self.get_model_by_role(ModelRole.SCANNER)
        if primary:
            return primary
        
        # Fallback to first available model
        if self.models:
            return list(self.models.values())[0]
        
        raise RuntimeError("No models available")
    
    def reason(self, history: List[Dict[str, str]], role: Optional[ModelRole] = None) -> str:
        """
        Perform reasoning with a specific model or primary model.
        
        Parameters:
            history: Conversation history
            role: Specific role to use (None for primary)
            
        Returns:
            Model response
        """
        if role:
            model = self.get_model_by_role(role)
            if not model:
                model = self.get_primary_model()
        else:
            model = self.get_primary_model()
        
        return model.reason(history)
    
    def output(self, prompt: str, temperature: float = 0.7, role: Optional[ModelRole] = None) -> str:
        """
        Generate output with a specific model or primary model.
        
        Parameters:
            prompt: Input prompt
            temperature: Temperature setting
            role: Specific role to use (None for primary)
            
        Returns:
            Model response
        """
        if role:
            model = self.get_model_by_role(role)
            if not model:
                model = self.get_primary_model()
        else:
            model = self.get_primary_model()
        
        return model.output(prompt, temperature)
    
    def collaborative_analysis(self, context: str, task: str) -> Dict[str, Any]:
        """
        Perform collaborative analysis using multiple models.
        
        Parameters:
            context: Context to analyze
            task: Task description
            
        Returns:
            Dictionary with analysis results from different models
        """
        results = {}
        
        # Get analyzer model
        analyzer = self.get_model_by_role(ModelRole.ANALYZER)
        if analyzer:
            analyzer_prompt = f"Analyze the following context for security vulnerabilities:\n\n{context}\n\nTask: {task}"
            results["analyzer"] = analyzer.output(analyzer_prompt, temperature=0.3)
        
        # Get attacker model
        attacker = self.get_model_by_role(ModelRole.ATTACKER)
        if attacker:
            attacker_prompt = f"Based on this context, suggest attack strategies:\n\n{context}\n\nTask: {task}"
            results["attacker"] = attacker.output(attacker_prompt, temperature=0.7)
        
        # Get reviewer model
        reviewer = self.get_model_by_role(ModelRole.REVIEWER)
        if reviewer and results:
            review_prompt = f"Review and validate these analysis results:\n\n{results}\n\nContext: {context}"
            results["reviewer"] = reviewer.output(review_prompt, temperature=0.2)
        
        # Record collaboration
        self.collaboration_history.append({
            "task": task,
            "context": context[:200],  # Truncate for storage
            "results": {k: v[:500] for k, v in results.items()},  # Truncate results
            "timestamp": time.time()
        })
        
        return results
    
    def get_available_models(self) -> List[str]:
        """Get list of available model names."""
        return list(self.models.keys())
    
    def get_model_info(self) -> Dict[str, Dict[str, Any]]:
        """Get information about all configured models."""
        info = {}
        for name, model in self.models.items():
            role = self.model_roles.get(name, ModelRole.SCANNER)
            config = self.model_configs.get(name, {})
            info[name] = {
                "role": role.value,
                "provider": config.get("provider", "unknown"),
                "model": config.get("model", "unknown"),
                "available": model is not None
            }
        return info

