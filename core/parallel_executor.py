"""
Parallel Vulnerability Testing Executor
Implements multi-phase parallel execution for faster security testing
"""
import time
import threading
import logging
from typing import Dict, List, Any, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from queue import Queue

logger = logging.getLogger(__name__)


class VulnerabilityCategory(Enum):
    """OWASP-aligned vulnerability categories for parallel testing"""
    INJECTION = "injection"           # SQL, NoSQL, OS Command, LDAP
    XSS = "xss"                       # Cross-Site Scripting
    AUTH = "auth"                     # Broken Authentication
    SSRF = "ssrf"                     # Server-Side Request Forgery
    IDOR = "idor"                     # Insecure Direct Object References
    MISCONFIG = "misconfig"           # Security Misconfiguration
    CRYPTO = "crypto"                 # Cryptographic Failures
    ACCESS_CONTROL = "access_control" # Broken Access Control


@dataclass
class TestTask:
    """Represents a single vulnerability test task"""
    task_id: str
    category: VulnerabilityCategory
    target_url: str
    test_name: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: int = 5  # 1-10, lower is higher priority
    dependencies: List[str] = field(default_factory=list)
    
    def __hash__(self):
        return hash(self.task_id)


@dataclass
class TestResult:
    """Result of a vulnerability test"""
    task_id: str
    category: VulnerabilityCategory
    success: bool
    vulnerability_found: bool
    severity: str = "none"  # none, low, medium, high, critical
    evidence: str = ""
    exploit_verified: bool = False
    execution_time: float = 0.0
    error: Optional[str] = None


class ParallelTestExecutor:
    """
    Executes vulnerability tests in parallel across multiple categories.
    
    Architecture:
    - Phase 1: Reconnaissance (sequential, builds target map)
    - Phase 2: Vulnerability Analysis (parallel by category)
    - Phase 3: Exploitation (parallel, validates findings)
    - Phase 4: Reporting (sequential, aggregates results)
    """
    
    def __init__(
        self,
        max_workers: int = 4,
        timeout_per_test: float = 60.0,
        validate_exploits: bool = True
    ):
        """
        Initialize parallel executor.
        
        Parameters:
            max_workers: Maximum concurrent test threads
            timeout_per_test: Timeout for individual tests in seconds
            validate_exploits: Only report vulnerabilities that can be exploited
        """
        self.max_workers = max_workers
        self.timeout_per_test = timeout_per_test
        self.validate_exploits = validate_exploits
        
        self.results: Dict[str, TestResult] = {}
        self.task_queue: Queue = Queue()
        self.completed_tasks: set = set()
        self.running = False
        
        # Category-specific test executors
        self.category_executors: Dict[VulnerabilityCategory, Callable] = {}
        
        # Execution statistics
        self.stats = {
            'total_tasks': 0,
            'completed_tasks': 0,
            'vulnerabilities_found': 0,
            'exploits_verified': 0,
            'start_time': None,
            'end_time': None
        }
    
    def register_executor(
        self,
        category: VulnerabilityCategory,
        executor: Callable[[TestTask], TestResult]
    ):
        """
        Register a test executor for a vulnerability category.
        
        Parameters:
            category: Vulnerability category to handle
            executor: Function that executes tests for this category
        """
        self.category_executors[category] = executor
        logger.info(f"[ParallelExecutor] Registered executor for {category.value}")
    
    def add_task(self, task: TestTask):
        """Add a test task to the queue"""
        self.task_queue.put(task)
        self.stats['total_tasks'] += 1
    
    def add_tasks(self, tasks: List[TestTask]):
        """Add multiple test tasks"""
        for task in tasks:
            self.add_task(task)
    
    def _execute_task(self, task: TestTask) -> TestResult:
        """Execute a single test task"""
        start_time = time.time()
        
        try:
            # Check if we have an executor for this category
            if task.category not in self.category_executors:
                return TestResult(
                    task_id=task.task_id,
                    category=task.category,
                    success=False,
                    vulnerability_found=False,
                    error=f"No executor registered for category: {task.category.value}"
                )
            
            # Execute the test
            executor = self.category_executors[task.category]
            result = executor(task)
            result.execution_time = time.time() - start_time
            
            # Validate exploit if required
            if self.validate_exploits and result.vulnerability_found:
                if not result.exploit_verified:
                    # Vulnerability found but not exploited - mark as unverified
                    logger.info(
                        f"[ParallelExecutor] Vulnerability in {task.task_id} not verified by exploit"
                    )
            
            return result
            
        except Exception as e:
            logger.error(f"[ParallelExecutor] Error executing {task.task_id}: {str(e)}")
            return TestResult(
                task_id=task.task_id,
                category=task.category,
                success=False,
                vulnerability_found=False,
                execution_time=time.time() - start_time,
                error=str(e)
            )
    
    def _can_execute_task(self, task: TestTask) -> bool:
        """Check if task dependencies are satisfied"""
        for dep_id in task.dependencies:
            if dep_id not in self.completed_tasks:
                return False
        return True
    
    def run_parallel(self, tasks: List[TestTask] = None) -> Dict[str, TestResult]:
        """
        Execute all tasks in parallel.
        
        Parameters:
            tasks: Optional list of tasks to execute (uses queue if None)
            
        Returns:
            Dictionary of task_id -> TestResult
        """
        if tasks:
            self.add_tasks(tasks)
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        # Collect all tasks from queue
        pending_tasks: List[TestTask] = []
        while not self.task_queue.empty():
            pending_tasks.append(self.task_queue.get())
        
        # Sort by priority
        pending_tasks.sort(key=lambda t: t.priority)
        
        logger.info(f"[ParallelExecutor] Starting parallel execution of {len(pending_tasks)} tasks")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit tasks that have no dependencies first
            futures = {}
            remaining_tasks = []
            
            for task in pending_tasks:
                if self._can_execute_task(task):
                    future = executor.submit(self._execute_task, task)
                    futures[future] = task
                else:
                    remaining_tasks.append(task)
            
            # Process completed tasks and submit dependent ones
            while futures or remaining_tasks:
                # Wait for at least one task to complete
                if futures:
                    for future in as_completed(futures, timeout=self.timeout_per_test):
                        task = futures.pop(future)
                        try:
                            result = future.result()
                            self.results[task.task_id] = result
                            self.completed_tasks.add(task.task_id)
                            self.stats['completed_tasks'] += 1
                            
                            if result.vulnerability_found:
                                self.stats['vulnerabilities_found'] += 1
                            if result.exploit_verified:
                                self.stats['exploits_verified'] += 1
                            
                            logger.info(
                                f"[ParallelExecutor] Completed {task.task_id}: "
                                f"vuln={result.vulnerability_found}, verified={result.exploit_verified}"
                            )
                            
                        except Exception as e:
                            logger.error(f"[ParallelExecutor] Task {task.task_id} failed: {str(e)}")
                            self.results[task.task_id] = TestResult(
                                task_id=task.task_id,
                                category=task.category,
                                success=False,
                                vulnerability_found=False,
                                error=str(e)
                            )
                            self.completed_tasks.add(task.task_id)
                        
                        break  # Process one at a time to check dependencies
                
                # Check for newly executable tasks
                still_remaining = []
                for task in remaining_tasks:
                    if self._can_execute_task(task):
                        future = executor.submit(self._execute_task, task)
                        futures[future] = task
                    else:
                        still_remaining.append(task)
                remaining_tasks = still_remaining
                
                # Prevent busy-waiting
                if not futures and remaining_tasks:
                    time.sleep(0.1)
        
        self.stats['end_time'] = time.time()
        self.running = False
        
        logger.info(
            f"[ParallelExecutor] Execution complete: "
            f"{self.stats['completed_tasks']}/{self.stats['total_tasks']} tasks, "
            f"{self.stats['vulnerabilities_found']} vulnerabilities, "
            f"{self.stats['exploits_verified']} verified exploits"
        )
        
        return self.results
    
    def run_by_category(
        self,
        tasks: List[TestTask],
        categories_parallel: bool = True
    ) -> Dict[VulnerabilityCategory, List[TestResult]]:
        """
        Execute tasks grouped by category.
        
        Parameters:
            tasks: List of test tasks
            categories_parallel: Run different categories in parallel
            
        Returns:
            Results grouped by category
        """
        # Group tasks by category
        category_tasks: Dict[VulnerabilityCategory, List[TestTask]] = {}
        for task in tasks:
            if task.category not in category_tasks:
                category_tasks[task.category] = []
            category_tasks[task.category].append(task)
        
        results_by_category: Dict[VulnerabilityCategory, List[TestResult]] = {}
        
        if categories_parallel:
            # Run all categories in parallel
            with ThreadPoolExecutor(max_workers=len(category_tasks)) as executor:
                category_futures = {}
                
                for category, cat_tasks in category_tasks.items():
                    # Create a sub-executor for each category
                    future = executor.submit(self._run_category_tasks, category, cat_tasks)
                    category_futures[future] = category
                
                for future in as_completed(category_futures):
                    category = category_futures[future]
                    try:
                        results_by_category[category] = future.result()
                    except Exception as e:
                        logger.error(f"[ParallelExecutor] Category {category} failed: {str(e)}")
                        results_by_category[category] = []
        else:
            # Run categories sequentially
            for category, cat_tasks in category_tasks.items():
                results_by_category[category] = self._run_category_tasks(category, cat_tasks)
        
        return results_by_category
    
    def _run_category_tasks(
        self,
        category: VulnerabilityCategory,
        tasks: List[TestTask]
    ) -> List[TestResult]:
        """Run all tasks for a single category"""
        results = []
        for task in tasks:
            result = self._execute_task(task)
            results.append(result)
        return results
    
    def get_verified_vulnerabilities(self) -> List[TestResult]:
        """
        Get only vulnerabilities that have been verified by exploitation.
        Implements "No Exploit, No Report" policy.
        """
        if self.validate_exploits:
            return [
                r for r in self.results.values()
                if r.vulnerability_found and r.exploit_verified
            ]
        else:
            return [
                r for r in self.results.values()
                if r.vulnerability_found
            ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get execution statistics"""
        stats = self.stats.copy()
        if stats['start_time'] and stats['end_time']:
            stats['total_time'] = stats['end_time'] - stats['start_time']
        else:
            stats['total_time'] = 0
        return stats


# Category-specific test executor templates

def create_injection_executor(page, llm) -> Callable[[TestTask], TestResult]:
    """Create an injection test executor"""
    def executor(task: TestTask) -> TestResult:
        # Implementation for SQL/NoSQL/Command injection testing
        # This would use the LLM to generate payloads and test them
        return TestResult(
            task_id=task.task_id,
            category=task.category,
            success=True,
            vulnerability_found=False,  # Placeholder
            exploit_verified=False
        )
    return executor


def create_xss_executor(page, llm) -> Callable[[TestTask], TestResult]:
    """Create a XSS test executor"""
    def executor(task: TestTask) -> TestResult:
        # Implementation for XSS testing
        return TestResult(
            task_id=task.task_id,
            category=task.category,
            success=True,
            vulnerability_found=False,
            exploit_verified=False
        )
    return executor


def create_auth_executor(page, llm) -> Callable[[TestTask], TestResult]:
    """Create an authentication test executor"""
    def executor(task: TestTask) -> TestResult:
        # Implementation for authentication bypass testing
        return TestResult(
            task_id=task.task_id,
            category=task.category,
            success=True,
            vulnerability_found=False,
            exploit_verified=False
        )
    return executor


def create_ssrf_executor(page, llm) -> Callable[[TestTask], TestResult]:
    """Create a SSRF test executor"""
    def executor(task: TestTask) -> TestResult:
        # Implementation for SSRF testing
        return TestResult(
            task_id=task.task_id,
            category=task.category,
            success=True,
            vulnerability_found=False,
            exploit_verified=False
        )
    return executor
