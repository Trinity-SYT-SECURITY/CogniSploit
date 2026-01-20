"""
Structured Tracing and Logging System
Provides execution traceability for agent operations
"""
import time
import json
import uuid
import logging
import threading
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger(__name__)


class TraceLevel(Enum):
    """Trace severity levels"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class TraceCategory(Enum):
    """Categories for trace events"""
    AGENT = "agent"
    TOOL = "tool"
    LLM = "llm"
    BROWSER = "browser"
    NETWORK = "network"
    EXPLOIT = "exploit"
    AUTH = "auth"
    AI_TEST = "ai_test"


@dataclass
class TraceSpan:
    """Represents a single traceable operation span"""
    span_id: str
    trace_id: str
    parent_id: Optional[str]
    name: str
    category: TraceCategory
    start_time: float
    end_time: Optional[float] = None
    level: TraceLevel = TraceLevel.INFO
    metadata: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict] = field(default_factory=list)
    error: Optional[str] = None
    
    @property
    def duration(self) -> float:
        """Get span duration in seconds"""
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time
    
    def add_event(self, name: str, data: Dict = None):
        """Add an event to this span"""
        self.events.append({
            'name': name,
            'timestamp': time.time(),
            'data': data or {}
        })
    
    def set_error(self, error: str):
        """Mark span as error"""
        self.error = error
        self.level = TraceLevel.ERROR
    
    def finish(self):
        """Mark span as finished"""
        self.end_time = time.time()
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'span_id': self.span_id,
            'trace_id': self.trace_id,
            'parent_id': self.parent_id,
            'name': self.name,
            'category': self.category.value,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': self.duration,
            'level': self.level.value,
            'metadata': self.metadata,
            'events': self.events,
            'error': self.error
        }


@dataclass
class Trace:
    """Collection of spans forming a complete trace"""
    trace_id: str
    name: str
    start_time: float
    end_time: Optional[float] = None
    spans: List[TraceSpan] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration(self) -> float:
        """Get total trace duration"""
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time
    
    def add_span(self, span: TraceSpan):
        """Add a span to this trace"""
        self.spans.append(span)
    
    def finish(self):
        """Mark trace as finished"""
        self.end_time = time.time()
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'trace_id': self.trace_id,
            'name': self.name,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': self.duration,
            'metadata': self.metadata,
            'spans': [s.to_dict() for s in self.spans]
        }


class TracingManager:
    """
    Manages tracing for the entire application.
    Thread-safe implementation for concurrent operations.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.traces: Dict[str, Trace] = {}
        self.current_trace_id: Optional[str] = None
        self.current_span_stack: List[str] = []
        self.exporters: List[Callable[[Trace], None]] = []
        self.output_dir: Optional[Path] = None
        self._lock = threading.Lock()
        self._initialized = True
    
    def configure(
        self,
        output_dir: str = None,
        enable_file_export: bool = True,
        enable_console: bool = True
    ):
        """
        Configure the tracing manager.
        
        Parameters:
            output_dir: Directory for trace output files
            enable_file_export: Write traces to files
            enable_console: Print traces to console
        """
        if output_dir:
            self.output_dir = Path(output_dir)
            self.output_dir.mkdir(parents=True, exist_ok=True)
        
        if enable_file_export and self.output_dir:
            self.exporters.append(self._file_exporter)
        
        if enable_console:
            self.exporters.append(self._console_exporter)
        
        logger.info(f"[Tracing] Configured with {len(self.exporters)} exporters")
    
    def start_trace(self, name: str, metadata: Dict = None) -> str:
        """
        Start a new trace.
        
        Parameters:
            name: Name of the trace
            metadata: Additional metadata
            
        Returns:
            Trace ID
        """
        trace_id = str(uuid.uuid4())
        
        trace = Trace(
            trace_id=trace_id,
            name=name,
            start_time=time.time(),
            metadata=metadata or {}
        )
        
        with self._lock:
            self.traces[trace_id] = trace
            self.current_trace_id = trace_id
        
        logger.debug(f"[Tracing] Started trace: {name} ({trace_id})")
        return trace_id
    
    def end_trace(self, trace_id: str = None):
        """End a trace and export it"""
        trace_id = trace_id or self.current_trace_id
        
        if not trace_id or trace_id not in self.traces:
            return
        
        trace = self.traces[trace_id]
        trace.finish()
        
        # Export trace
        for exporter in self.exporters:
            try:
                exporter(trace)
            except Exception as e:
                logger.error(f"[Tracing] Exporter failed: {str(e)}")
        
        with self._lock:
            if self.current_trace_id == trace_id:
                self.current_trace_id = None
        
        logger.debug(f"[Tracing] Ended trace: {trace.name} (duration: {trace.duration:.2f}s)")
    
    @contextmanager
    def span(
        self,
        name: str,
        category: TraceCategory,
        metadata: Dict = None
    ):
        """
        Context manager for creating a span.
        
        Usage:
            with tracer.span("my_operation", TraceCategory.AGENT) as span:
                # Do work
                span.add_event("step1", {"data": "value"})
        """
        span = self.start_span(name, category, metadata)
        try:
            yield span
        except Exception as e:
            span.set_error(str(e))
            raise
        finally:
            self.end_span(span.span_id)
    
    def start_span(
        self,
        name: str,
        category: TraceCategory,
        metadata: Dict = None
    ) -> TraceSpan:
        """
        Start a new span in the current trace.
        
        Parameters:
            name: Name of the span
            category: Category of operation
            metadata: Additional metadata
            
        Returns:
            TraceSpan object
        """
        span_id = str(uuid.uuid4())
        trace_id = self.current_trace_id
        
        # Get parent span
        parent_id = None
        if self.current_span_stack:
            parent_id = self.current_span_stack[-1]
        
        span = TraceSpan(
            span_id=span_id,
            trace_id=trace_id or "",
            parent_id=parent_id,
            name=name,
            category=category,
            start_time=time.time(),
            metadata=metadata or {}
        )
        
        with self._lock:
            self.current_span_stack.append(span_id)
            
            if trace_id and trace_id in self.traces:
                self.traces[trace_id].add_span(span)
        
        logger.debug(f"[Tracing] Started span: {name}")
        return span
    
    def end_span(self, span_id: str):
        """End a span"""
        with self._lock:
            if span_id in self.current_span_stack:
                self.current_span_stack.remove(span_id)
        
        # Find and finish the span
        if self.current_trace_id and self.current_trace_id in self.traces:
            trace = self.traces[self.current_trace_id]
            for span in trace.spans:
                if span.span_id == span_id:
                    span.finish()
                    logger.debug(f"[Tracing] Ended span: {span.name} (duration: {span.duration:.2f}s)")
                    break
    
    def add_event(self, name: str, data: Dict = None):
        """Add an event to the current span"""
        if not self.current_span_stack:
            return
        
        span_id = self.current_span_stack[-1]
        
        if self.current_trace_id and self.current_trace_id in self.traces:
            trace = self.traces[self.current_trace_id]
            for span in trace.spans:
                if span.span_id == span_id:
                    span.add_event(name, data)
                    break
    
    def _file_exporter(self, trace: Trace):
        """Export trace to JSON file"""
        if not self.output_dir:
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"trace_{trace.name}_{timestamp}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(trace.to_dict(), f, indent=2)
        
        logger.info(f"[Tracing] Exported trace to {filepath}")
    
    def _console_exporter(self, trace: Trace):
        """Export trace summary to console"""
        print(f"\n{'='*60}")
        print(f"TRACE: {trace.name}")
        print(f"ID: {trace.trace_id}")
        print(f"Duration: {trace.duration:.2f}s")
        print(f"Spans: {len(trace.spans)}")
        print(f"{'='*60}")
        
        for span in trace.spans:
            indent = "  " if span.parent_id else ""
            status = "[ERROR]" if span.error else "[OK]"
            print(f"{indent}{status} {span.name} ({span.category.value}) - {span.duration:.2f}s")
            
            if span.error:
                print(f"{indent}  Error: {span.error}")
        
        print(f"{'='*60}\n")
    
    def get_trace_summary(self, trace_id: str = None) -> Dict:
        """Get summary of a trace"""
        trace_id = trace_id or self.current_trace_id
        
        if not trace_id or trace_id not in self.traces:
            return {}
        
        trace = self.traces[trace_id]
        
        # Calculate statistics
        spans_by_category = {}
        total_errors = 0
        
        for span in trace.spans:
            cat = span.category.value
            if cat not in spans_by_category:
                spans_by_category[cat] = {'count': 0, 'duration': 0}
            spans_by_category[cat]['count'] += 1
            spans_by_category[cat]['duration'] += span.duration
            
            if span.error:
                total_errors += 1
        
        return {
            'trace_id': trace_id,
            'name': trace.name,
            'duration': trace.duration,
            'total_spans': len(trace.spans),
            'total_errors': total_errors,
            'spans_by_category': spans_by_category
        }


# Global tracer instance
tracer = TracingManager()


# Decorator for tracing functions
def trace_function(category: TraceCategory, name: str = None):
    """
    Decorator to trace function execution.
    
    Usage:
        @trace_function(TraceCategory.AGENT, "my_function")
        def my_function():
            pass
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            func_name = name or func.__name__
            with tracer.span(func_name, category) as span:
                span.metadata['args'] = str(args)[:200]
                span.metadata['kwargs'] = str(kwargs)[:200]
                result = func(*args, **kwargs)
                return result
        return wrapper
    return decorator


# Convenience functions
def start_trace(name: str, metadata: Dict = None) -> str:
    """Start a new trace"""
    return tracer.start_trace(name, metadata)


def end_trace(trace_id: str = None):
    """End current trace"""
    tracer.end_trace(trace_id)


def span(name: str, category: TraceCategory, metadata: Dict = None):
    """Create a span context manager"""
    return tracer.span(name, category, metadata)


def add_event(name: str, data: Dict = None):
    """Add event to current span"""
    tracer.add_event(name, data)
