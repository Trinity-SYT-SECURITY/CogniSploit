"""LLM Module for Security Testing"""

from .llm import LLM
try:
    from .multi_model_llm import MultiModelLLM, ModelRole
    __all__ = ['LLM', 'MultiModelLLM', 'ModelRole']
except ImportError:
    __all__ = ['LLM']
