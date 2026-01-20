import json
from llm.llm import LLM
from pathlib import Path

class Reporter:
    """
    Automated security findings aggregator and report generator.
    
    Processes LLM-driven security assessment conversations to extract
    actionable vulnerability intelligence. Generates structured reports
    with severity classifications and remediation guidance.
    """

    def __init__(self, starting_url, model_provider: str = "openai", model_name: str = None, debug: bool = False):
        """
        Configure the report generation pipeline.

        Parameters:
            starting_url: Target application base URL
            model_provider: AI backend selection ("openai" or "anthropic")
            model_name: Specific model identifier (uses provider default if None)
            debug: Enable verbose diagnostic output
        """
        self.debug = debug
        self.llm = LLM(model_provider=model_provider, model_name=model_name, debug=debug)
        self.reports = []
        self.starting_url = starting_url
        self.filename = str(self.starting_url).replace("https://", "").replace("http://", "").replace("/", "_")

    def report(self, history):
        """
        Analyze conversation history to identify ALL security findings and attack points.

        Comprehensively analyzes the conversation to document:
        - Confirmed vulnerabilities
        - Potential attack vectors
        - Security misconfigurations
        - Information disclosure
        - Attack attempts and their results
        - Tools used and their findings

        Parameters:
            history: List of conversation messages between agent and system

        Returns:
            Tuple of (bool, str) indicating if any findings were found and detailed report
        """
        system_prompt = f"""
        You are a comprehensive security assessment analyst. Your job is to analyze a conversation between a security testing agent and document ALL security-related findings, attack attempts, and potential issues discovered during the testing process.

        You must document EVERYTHING that could be relevant for security analysis:

        1. **CONFIRMED VULNERABILITIES** (if any):
           - Clear proof of successful exploitation
           - Specific technical details and payloads
           - Evidence of successful attack

        2. **POTENTIAL ATTACK VECTORS**:
           - Forms, parameters, or endpoints that could be vulnerable
           - Input fields that accept user data
           - API endpoints that might be exploitable
           - File upload capabilities
           - Authentication mechanisms

        3. **SECURITY MISCONFIGURATIONS**:
           - Missing security headers
           - Debug information exposure
           - Default credentials
           - Unnecessary services running
           - Open ports and services

        4. **INFORMATION DISCLOSURE**:
           - Error messages revealing system information
           - Directory listings
           - Version information exposure
           - Internal file paths
           - Database errors

        5. **ATTACK ATTEMPTS AND RESULTS**:
           - What attacks were attempted
           - What tools were used
           - What responses were received
           - What errors or unexpected behavior occurred
           - What was learned from each attempt

        6. **TOOLS AND SCANNING RESULTS**:
           - External tools executed and their findings
           - Port scan results
           - Directory enumeration results
           - Vulnerability scan outputs
           - Any other security tool results

        7. **TARGET ANALYSIS**:
           - Technologies identified
           - Services running
           - File structure discovered
           - Authentication mechanisms
           - Business logic insights

        IMPORTANT: Do NOT be overly strict. Document everything that could be useful for security analysis, even if it's not a confirmed vulnerability. The goal is to provide a complete picture of the security assessment.

        Create a comprehensive report that includes:
        - Executive summary of all findings
        - Detailed breakdown of each category above
        - Technical details and evidence
        - Risk assessment for each finding
        - Recommendations for further testing
        """

        system_prompt = [{"role": "system", "content": system_prompt}]
        history.append({"role": "user", "content": "Please analyze our conversation history comprehensively and document ALL security findings, attack attempts, tools used, and potential issues discovered during the security testing process."})
        
        # Use the correct LLM method based on provider
        try:
            report = self.llm.reason(system_prompt + history)
        except AttributeError:
            # Fallback to chat method if reason method doesn't exist
            try:
                report = self.llm.chat(system_prompt + history)
            except AttributeError:
                # Final fallback to output method
                combined_messages = "\n".join([f"{msg['role']}: {msg['content']}" for msg in system_prompt + history])
                report = self.llm.output(combined_messages)

        # Check if any findings were documented
        has_findings = self.parse_report_for_findings(report)

        # Save all reports (not just successful exploits)
        self.reports.append(report)
        self.save_reports()
        
        return has_findings, report

    def parse_report(self, report):
        """
        Parse a vulnerability report to determine if exploit was successful.

        Parameters:
            report: String containing the vulnerability report

        Returns:
            bool indicating if report demonstrates successful exploit
        """
        system_prompt = f"""
        You are a report parser whose task is to look at a report and its evaluation and return a boolean value indicating whether the report resulted in a successful exploit or not.

        Only return 1 word, either "yes" if the report resulted in a successful exploit or "no" if it did not.
        """

        system_prompt = [{"role": "system", "content": system_prompt}]
        
        # Use the correct LLM method based on provider
        try:
            response = self.llm.reason(system_prompt + [{"role": "user", "content": report}])
        except AttributeError:
            # Fallback to chat method if reason method doesn't exist
            try:
                response = self.llm.chat(system_prompt + [{"role": "user", "content": report}])
            except AttributeError:
                # Final fallback to output method
                combined_messages = "\n".join([f"{msg['role']}: {msg['content']}" for msg in system_prompt + [{"role": "user", "content": report}]])
                response = self.llm.output(combined_messages)
        
        response = str(response)
        return "yes" in response
    
    def parse_report_for_findings(self, report):
        """
        Parse a comprehensive security report to determine if any findings were documented.

        Parameters:
            report: String containing the comprehensive security report

        Returns:
            bool indicating if report contains any security findings
        """
        system_prompt = f"""
        You are a security analyzer. Your task is to determine if the report contains ANY security findings, attack attempts, or relevant information discovered during security testing.

        Look for ANY of the following:
        - Confirmed vulnerabilities
        - Potential attack vectors
        - Security misconfigurations
        - Information disclosure
        - Attack attempts and their results
        - Tools used and their findings
        - Target analysis and discovered information
        - Any other security-related findings

        Only return 1 word: "yes" if ANY findings were documented, or "no" if the report shows no findings at all.

        IMPORTANT: Even if no confirmed vulnerabilities were found, if the report documents attack attempts, tools used, target analysis, or any other security-related information, return "yes".
        """

        system_prompt = [{"role": "system", "content": system_prompt}]
        
        # Use the correct LLM method based on provider
        try:
            response = self.llm.reason(system_prompt + [{"role": "user", "content": report}])
        except AttributeError:
            # Fallback to chat method if reason method doesn't exist
            try:
                response = self.llm.chat(system_prompt + [{"role": "user", "content": report}])
            except AttributeError:
                # Final fallback to output method
                combined_messages = "\n".join([f"{msg['role']}: {msg['content']}" for msg in system_prompt + [{"role": "user", "content": report}]])
                response = self.llm.output(combined_messages)
        
        response = str(response)
        return "yes" in response

    def save_reports(self):
        """Save all vulnerability reports to a text file."""
        report_path = Path("scan_output") / f"{self.filename}.md"
        with open(report_path, "w") as f:
            f.write("\n\n-------\n\n".join(self.reports))

    def generate_summary_report(self):
        """
        Generate a comprehensive markdown summary of all findings.
        
        Reads all previously saved reports and creates a well-formatted markdown
        document summarizing the vulnerabilities found, their severity, and
        technical details.
        """
        # Load all reports from file
        try:
            report_path = Path("scan_output") / f"{self.filename}.md"
            with open(report_path, "r", encoding='utf-8') as f:
                report_content = f.read()
                
            # Check if there are actual reports to summarize
            if report_content.strip():
                system_prompt = f"""
                You are a comprehensive security summarizer. Your task is to analyze ALL security findings and create a detailed markdown summary report that covers everything discovered during the security assessment.

                You must document ALL of the following categories (even if some are empty):

                1. **EXECUTIVE SUMMARY**:
                   - Overall assessment results
                   - Key findings summary
                   - Risk level assessment

                2. **CONFIRMED VULNERABILITIES** (if any):
                   - Description and severity
                   - Affected endpoint/component
                   - Exploitation steps and payloads
                   - Proof of successful exploitation
                   - Impact assessment

                3. **POTENTIAL ATTACK VECTORS**:
                   - Forms, parameters, endpoints identified
                   - Input fields and their potential risks
                   - API endpoints that could be vulnerable
                   - File upload capabilities
                   - Authentication mechanisms

                4. **SECURITY MISCONFIGURATIONS**:
                   - Missing security headers
                   - Debug information exposure
                   - Default credentials found
                   - Unnecessary services running
                   - Open ports and services

                5. **INFORMATION DISCLOSURE**:
                   - Error messages and system information
                   - Directory listings discovered
                   - Version information exposed
                   - Internal file paths revealed
                   - Database errors or information

                6. **ATTACK ATTEMPTS AND RESULTS**:
                   - What attacks were attempted
                   - Tools and techniques used
                   - Responses received
                   - Errors or unexpected behavior
                   - Lessons learned from each attempt

                7. **TOOLS AND SCANNING RESULTS**:
                   - External tools executed
                   - Port scan results
                   - Directory enumeration findings
                   - Vulnerability scan outputs
                   - Any other security tool results

                8. **TARGET ANALYSIS**:
                   - Technologies identified
                   - Services running
                   - File structure discovered
                   - Authentication mechanisms
                   - Business logic insights

                9. **RECOMMENDATIONS**:
                   - Immediate actions needed
                   - Further testing suggestions
                   - Security improvements
                   - Risk mitigation strategies

                Format the output as a proper markdown document with:
                - Clear executive summary
                - Comprehensive table of contents
                - Detailed findings in separate sections
                - Technical details in code blocks
                - Risk assessments for each finding
                - Clear headings and structure
                
                IMPORTANT: Document EVERYTHING discovered, even if it's not a confirmed vulnerability. The goal is to provide a complete picture of the security assessment.
                """

                system_prompt = [{"role": "system", "content": system_prompt}]
                
                # Use the correct LLM method based on provider
                try:
                    summary = self.llm.reason(system_prompt + [{"role": "user", "content": report_content}])
                except AttributeError:
                    # Fallback to chat method if reason method doesn't exist
                    try:
                        summary = self.llm.chat(system_prompt + [{"role": "user", "content": report_content}])
                    except AttributeError:
                        # Final fallback to output method
                        combined_messages = "\n".join([f"{msg['role']}: {msg['content']}" for msg in system_prompt + [{"role": "user", "content": report_content}]])
                        summary = self.llm.output(combined_messages)
            else:
                # No vulnerabilities were found, create a clean "no findings" report
                summary = self._generate_no_findings_report()
        except FileNotFoundError:
            # No report file exists, create a clean "no findings" report
            summary = self._generate_no_findings_report()
            
        # Save markdown summary report
        with open(f"scan_output/{self.filename}_summary.md", "w", encoding='utf-8') as f:
            f.write(summary)
            
    def _generate_no_findings_report(self):
        """Generate a comprehensive report even when no vulnerabilities were found."""
        return f"""# Security Assessment Summary: {self.starting_url}

## Executive Summary

A comprehensive security assessment was conducted on **{self.starting_url}** using automated scanning techniques, manual testing, and external security tools. While no exploitable vulnerabilities were identified, this report documents all findings, attack attempts, and security-related information discovered during the assessment.

## Assessment Details

- **Target:** {self.starting_url}
- **Assessment Date:** Auto-generated report
- **Assessment Type:** Web application security testing
- **Testing Methodology:** Combination of automated scanning, manual testing, and external security tools

## Assessment Scope

This assessment covered:
- Web application vulnerability testing
- Port scanning and service enumeration
- Directory and file enumeration
- Authentication mechanism testing
- Input validation testing
- Security header analysis
- Technology fingerprinting
- Business logic analysis

## Findings Summary

### Confirmed Vulnerabilities
**None identified** - No exploitable security vulnerabilities were confirmed during this assessment.

### Potential Attack Vectors
**Documented in detailed findings** - All discovered forms, parameters, endpoints, and input fields have been documented for further analysis.

### Security Misconfigurations
**Documented in detailed findings** - Any security misconfigurations, missing headers, or exposed information has been documented.

### Information Disclosure
**Documented in detailed findings** - Any information disclosure, error messages, or system information revealed during testing has been documented.

### Attack Attempts and Results
**Documented in detailed findings** - All attack attempts, tools used, and responses received have been documented for analysis.

### Tools and Scanning Results
**Documented in detailed findings** - Results from all external security tools, port scans, and vulnerability scans have been documented.

### Target Analysis
**Documented in detailed findings** - All discovered technologies, services, file structures, and business logic insights have been documented.

## Risk Assessment

- **Overall Risk Level:** LOW (no confirmed vulnerabilities)
- **Information Disclosure Risk:** Documented in findings
- **Attack Surface:** Documented in findings
- **Security Posture:** Documented in findings

## Recommendations

1. **Review All Findings:** Carefully review all documented findings, even if they don't represent confirmed vulnerabilities
2. **Address Information Disclosure:** Fix any information disclosure issues identified
3. **Implement Security Headers:** Add missing security headers if identified
4. **Regular Security Testing:** Continue to perform regular security assessments
5. **Security Monitoring:** Implement or maintain security monitoring systems
6. **Keep Dependencies Updated:** Regularly update all software dependencies
7. **Security Training:** Ensure development team stays current on security best practices

## Conclusion

While no exploitable security vulnerabilities were identified, this assessment provides a comprehensive view of the target's security posture, attack surface, and potential areas for improvement. The detailed findings should be reviewed to identify any security improvements that could be implemented.

**Note:** This report documents ALL findings discovered during testing, not just confirmed vulnerabilities. This comprehensive approach ensures that no security-related information is overlooked.

---
"""
