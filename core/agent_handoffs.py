"""
Agent Handoff System
Enables specialized agents to collaborate on security testing tasks
"""
import time
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class AgentRole(Enum):
    """Specialized agent roles for security testing"""
    RECON = "reconnaissance"           # Initial target mapping
    ANALYZER = "vulnerability_analyzer" # Identify potential vulnerabilities
    EXPLOITER = "exploitation"          # Validate vulnerabilities with exploits
    VALIDATOR = "result_validator"      # Validate findings before reporting
    REPORTER = "report_generator"       # Generate final reports
    AI_TESTER = "ai_security_tester"    # Test AI/LLM systems


@dataclass
class HandoffContext:
    """Context passed between agents during handoffs"""
    source_agent: str
    target_agent: str
    task_type: str
    data: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    def add_finding(self, finding: Dict):
        """Add a finding to the context"""
        self.findings.append({
            **finding,
            'added_by': self.source_agent,
            'timestamp': time.time()
        })
    
    def get_findings_by_type(self, finding_type: str) -> List[Dict]:
        """Get findings filtered by type"""
        return [f for f in self.findings if f.get('type') == finding_type]


class BaseAgent(ABC):
    """Base class for specialized security testing agents"""
    
    def __init__(
        self,
        name: str,
        role: AgentRole,
        llm = None,
        model_name: str = None
    ):
        self.name = name
        self.role = role
        self.llm = llm
        self.model_name = model_name
        self.handoffs: List['BaseAgent'] = []
        self.execution_history: List[Dict] = []
    
    def register_handoff(self, target_agent: 'BaseAgent'):
        """Register an agent that this agent can hand off to"""
        if target_agent not in self.handoffs:
            self.handoffs.append(target_agent)
            logger.info(f"[{self.name}] Registered handoff to {target_agent.name}")
    
    @abstractmethod
    def execute(self, context: HandoffContext) -> HandoffContext:
        """Execute the agent's task and return updated context"""
        pass
    
    def handoff_to(
        self,
        target_agent: 'BaseAgent',
        context: HandoffContext
    ) -> HandoffContext:
        """Hand off task to another agent"""
        if target_agent not in self.handoffs:
            raise ValueError(f"Agent {target_agent.name} not registered for handoffs")
        
        # Update context for handoff
        context.source_agent = self.name
        context.target_agent = target_agent.name
        context.timestamp = time.time()
        
        logger.info(f"[Handoff] {self.name} -> {target_agent.name}")
        
        # Execute target agent
        return target_agent.execute(context)
    
    def _record_execution(self, context: HandoffContext, result: Any):
        """Record execution in history"""
        self.execution_history.append({
            'timestamp': time.time(),
            'context': context,
            'result': result
        })


class ReconAgent(BaseAgent):
    """Agent specialized in reconnaissance and target mapping"""
    
    def __init__(self, llm=None, model_name: str = None):
        super().__init__(
            name="ReconAgent",
            role=AgentRole.RECON,
            llm=llm,
            model_name=model_name
        )
    
    def execute(self, context: HandoffContext) -> HandoffContext:
        """Perform reconnaissance on target"""
        logger.info(f"[{self.name}] Starting reconnaissance")
        
        target_url = context.data.get('target_url', '')
        
        # Reconnaissance tasks:
        # 1. Technology fingerprinting
        # 2. Endpoint enumeration
        # 3. Authentication mechanism detection
        # 4. AI/LLM interface detection
        
        recon_results = {
            'type': 'reconnaissance',
            'target_url': target_url,
            'technologies': [],
            'endpoints': [],
            'auth_mechanisms': [],
            'ai_interfaces': [],
            'attack_surface': {}
        }
        
        # Use LLM to analyze the target if available
        if self.llm:
            page_content = context.data.get('page_content', '')
            if page_content:
                analysis_prompt = f"""
                Analyze this web page content for security testing reconnaissance:
                
                Page Content (truncated):
                {page_content[:5000]}
                
                Identify:
                1. Technologies and frameworks used
                2. API endpoints and parameters
                3. Authentication mechanisms
                4. Potential AI/LLM chat interfaces
                5. Attack surface areas
                
                Format as structured analysis.
                """
                try:
                    analysis = self.llm.output(analysis_prompt)
                    recon_results['llm_analysis'] = analysis
                except Exception as e:
                    logger.error(f"[{self.name}] LLM analysis failed: {str(e)}")
        
        context.add_finding(recon_results)
        context.metadata['recon_complete'] = True
        
        self._record_execution(context, recon_results)
        
        return context


class VulnerabilityAnalyzerAgent(BaseAgent):
    """Agent specialized in identifying potential vulnerabilities"""
    
    def __init__(self, llm=None, model_name: str = None):
        super().__init__(
            name="VulnAnalyzer",
            role=AgentRole.ANALYZER,
            llm=llm,
            model_name=model_name
        )
    
    def execute(self, context: HandoffContext) -> HandoffContext:
        """Analyze target for potential vulnerabilities"""
        logger.info(f"[{self.name}] Starting vulnerability analysis")
        
        # Get recon data
        recon_findings = context.get_findings_by_type('reconnaissance')
        
        vulnerability_hypotheses = []
        
        # Analyze for common vulnerability patterns
        vulnerability_checks = [
            ('injection', self._check_injection_points),
            ('xss', self._check_xss_points),
            ('auth', self._check_auth_weaknesses),
            ('ssrf', self._check_ssrf_points),
            ('idor', self._check_idor_points),
        ]
        
        for vuln_type, check_func in vulnerability_checks:
            findings = check_func(context, recon_findings)
            vulnerability_hypotheses.extend(findings)
        
        analysis_result = {
            'type': 'vulnerability_analysis',
            'hypotheses': vulnerability_hypotheses,
            'hypothesis_count': len(vulnerability_hypotheses)
        }
        
        context.add_finding(analysis_result)
        context.metadata['analysis_complete'] = True
        
        self._record_execution(context, analysis_result)
        
        return context
    
    def _check_injection_points(self, context: HandoffContext, recon: List[Dict]) -> List[Dict]:
        """Check for injection vulnerability points"""
        findings = []
        # Implementation would analyze forms, URLs, API endpoints
        return findings
    
    def _check_xss_points(self, context: HandoffContext, recon: List[Dict]) -> List[Dict]:
        """Check for XSS vulnerability points"""
        findings = []
        return findings
    
    def _check_auth_weaknesses(self, context: HandoffContext, recon: List[Dict]) -> List[Dict]:
        """Check for authentication weaknesses"""
        findings = []
        return findings
    
    def _check_ssrf_points(self, context: HandoffContext, recon: List[Dict]) -> List[Dict]:
        """Check for SSRF vulnerability points"""
        findings = []
        return findings
    
    def _check_idor_points(self, context: HandoffContext, recon: List[Dict]) -> List[Dict]:
        """Check for IDOR vulnerability points"""
        findings = []
        return findings


class ExploitationAgent(BaseAgent):
    """Agent specialized in validating vulnerabilities through exploitation"""
    
    def __init__(self, llm=None, model_name: str = None, page=None):
        super().__init__(
            name="Exploiter",
            role=AgentRole.EXPLOITER,
            llm=llm,
            model_name=model_name
        )
        self.page = page  # Playwright page for browser interaction
    
    def execute(self, context: HandoffContext) -> HandoffContext:
        """Attempt to exploit identified vulnerabilities"""
        logger.info(f"[{self.name}] Starting exploitation phase")
        
        # Get vulnerability hypotheses
        analysis_findings = context.get_findings_by_type('vulnerability_analysis')
        
        verified_vulnerabilities = []
        
        for analysis in analysis_findings:
            hypotheses = analysis.get('hypotheses', [])
            
            for hypothesis in hypotheses:
                # Attempt to exploit each hypothesis
                exploit_result = self._attempt_exploit(hypothesis, context)
                
                if exploit_result.get('success'):
                    verified_vulnerabilities.append({
                        'hypothesis': hypothesis,
                        'exploit_result': exploit_result,
                        'evidence': exploit_result.get('evidence', ''),
                        'severity': self._calculate_severity(exploit_result)
                    })
        
        exploitation_result = {
            'type': 'exploitation',
            'verified_vulnerabilities': verified_vulnerabilities,
            'verified_count': len(verified_vulnerabilities)
        }
        
        context.add_finding(exploitation_result)
        context.metadata['exploitation_complete'] = True
        
        self._record_execution(context, exploitation_result)
        
        return context
    
    def _attempt_exploit(self, hypothesis: Dict, context: HandoffContext) -> Dict:
        """Attempt to exploit a vulnerability hypothesis"""
        # Implementation would use browser automation to test
        return {
            'success': False,
            'evidence': '',
            'error': None
        }
    
    def _calculate_severity(self, exploit_result: Dict) -> str:
        """Calculate severity based on exploit result"""
        # Implementation would assess impact
        return 'medium'


class ResultValidatorAgent(BaseAgent):
    """Agent specialized in validating and cleaning results"""
    
    def __init__(self, llm=None, model_name: str = None):
        super().__init__(
            name="Validator",
            role=AgentRole.VALIDATOR,
            llm=llm,
            model_name=model_name
        )
    
    def execute(self, context: HandoffContext) -> HandoffContext:
        """Validate exploitation results before reporting"""
        logger.info(f"[{self.name}] Validating results")
        
        exploitation_findings = context.get_findings_by_type('exploitation')
        
        validated_findings = []
        
        for finding in exploitation_findings:
            verified_vulns = finding.get('verified_vulnerabilities', [])
            
            for vuln in verified_vulns:
                # Validate each finding
                if self._validate_finding(vuln, context):
                    validated_findings.append(vuln)
                else:
                    logger.info(f"[{self.name}] Discarded unverified finding")
        
        validation_result = {
            'type': 'validation',
            'validated_findings': validated_findings,
            'validated_count': len(validated_findings)
        }
        
        context.add_finding(validation_result)
        context.metadata['validation_complete'] = True
        
        self._record_execution(context, validation_result)
        
        return context
    
    def _validate_finding(self, finding: Dict, context: HandoffContext) -> bool:
        """Validate a single finding"""
        # Check for required evidence
        if not finding.get('evidence'):
            return False
        
        # Check that exploit was successful
        exploit_result = finding.get('exploit_result', {})
        if not exploit_result.get('success'):
            return False
        
        return True


class AgentOrchestrator:
    """Orchestrates agent handoffs and execution flow"""
    
    def __init__(self):
        self.agents: Dict[AgentRole, BaseAgent] = {}
        self.execution_flow: List[AgentRole] = []
        self.execution_history: List[Dict] = []
    
    def register_agent(self, agent: BaseAgent):
        """Register an agent with the orchestrator"""
        self.agents[agent.role] = agent
        logger.info(f"[Orchestrator] Registered {agent.name} ({agent.role.value})")
    
    def set_execution_flow(self, flow: List[AgentRole]):
        """Set the order of agent execution"""
        self.execution_flow = flow
        
        # Set up handoffs between consecutive agents
        for i in range(len(flow) - 1):
            current_role = flow[i]
            next_role = flow[i + 1]
            
            if current_role in self.agents and next_role in self.agents:
                self.agents[current_role].register_handoff(self.agents[next_role])
    
    def execute(self, initial_context: HandoffContext) -> HandoffContext:
        """Execute the full agent pipeline"""
        logger.info("[Orchestrator] Starting agent pipeline execution")
        
        context = initial_context
        
        for role in self.execution_flow:
            if role not in self.agents:
                logger.warning(f"[Orchestrator] No agent registered for {role.value}")
                continue
            
            agent = self.agents[role]
            
            try:
                logger.info(f"[Orchestrator] Executing {agent.name}")
                start_time = time.time()
                
                context = agent.execute(context)
                
                execution_time = time.time() - start_time
                self.execution_history.append({
                    'agent': agent.name,
                    'role': role.value,
                    'timestamp': time.time(),
                    'execution_time': execution_time,
                    'success': True
                })
                
            except Exception as e:
                logger.error(f"[Orchestrator] Error in {agent.name}: {str(e)}")
                self.execution_history.append({
                    'agent': agent.name,
                    'role': role.value,
                    'timestamp': time.time(),
                    'success': False,
                    'error': str(e)
                })
        
        logger.info("[Orchestrator] Pipeline execution complete")
        return context
    
    def get_execution_summary(self) -> Dict[str, Any]:
        """Get summary of execution history"""
        return {
            'total_agents': len(self.execution_flow),
            'executed': len(self.execution_history),
            'successful': sum(1 for e in self.execution_history if e.get('success')),
            'failed': sum(1 for e in self.execution_history if not e.get('success')),
            'history': self.execution_history
        }


def create_default_pipeline(llm=None, page=None) -> AgentOrchestrator:
    """Create a default security testing pipeline"""
    orchestrator = AgentOrchestrator()
    
    # Create agents
    recon = ReconAgent(llm=llm)
    analyzer = VulnerabilityAnalyzerAgent(llm=llm)
    exploiter = ExploitationAgent(llm=llm, page=page)
    validator = ResultValidatorAgent(llm=llm)
    
    # Register agents
    orchestrator.register_agent(recon)
    orchestrator.register_agent(analyzer)
    orchestrator.register_agent(exploiter)
    orchestrator.register_agent(validator)
    
    # Set execution flow
    orchestrator.set_execution_flow([
        AgentRole.RECON,
        AgentRole.ANALYZER,
        AgentRole.EXPLOITER,
        AgentRole.VALIDATOR
    ])
    
    return orchestrator
