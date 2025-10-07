"""
Pipeline orchestrator - coordinates all scanning stages with policy validation.
"""

import json
import time
from datetime import datetime
from pathlib import Path

from utils.logger import log_info, log_error, log_warning
from policy.policy_engine import PolicyEngine
from recon.passive import PassiveRecon
from recon.portscan import PortScanner
from scanners.nuclei_runner import NucleiRunner
from scanners.crawler import Crawler
from triage.triage_ai import TriageEngine
from reports.generator import ReportGenerator
from db.storage import save_run, save_finding, get_run_findings


class Orchestrator:
    """Orchestrates the complete scanning pipeline with policy enforcement."""
    
    def __init__(self, config):
        """
        Initialize orchestrator with configuration.
        
        Args:
            config (dict): Configuration dictionary
        """
        self.config = config
        self.policy_engine = PolicyEngine(config)
        self.passive_recon = PassiveRecon(config)
        self.port_scanner = PortScanner(config)
        self.nuclei_runner = NucleiRunner(config)
        self.crawler = Crawler(config)
        self.triage_engine = TriageEngine(config)
        self.report_generator = ReportGenerator(config)
    
    def run_pipeline(self, target, mode, scope_file=None, allow_unblock=False, output_dir=None):
        """
        Run the complete scanning pipeline for a target.
        
        Args:
            target (str): Target domain or IP
            mode (str): Scan mode (passive-only, safe-scan, full-scan-with-validation)
            scope_file (str): Path to scope definition file
            allow_unblock (bool): Allow manual unblocking of policy decisions
            output_dir (str): Custom output directory
        
        Returns:
            dict: Result dictionary with success status and run_id
        """
        run_id = f"{int(time.time())}_{target.replace('.', '_')}"
        start_time = datetime.now()
        
        log_info(f"Starting pipeline for {target} (mode: {mode}, run_id: {run_id})")
        
        # Create output directory
        if output_dir:
            output_path = Path(output_dir) / run_id
        else:
            output_path = Path(self.config['OUTPUT_DIR']) / run_id
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save run to database
        save_run(run_id, target, mode, str(output_path))
        
        try:
            # Step 1: Policy validation - Check if target is in scope
            log_info("Step 1: Validating target scope...")
            scope_decision = self.policy_engine.is_target_in_scope(target, scope_file)
            
            if scope_decision['decision'] == 'BLOCKED':
                log_error(f"Target BLOCKED by policy: {scope_decision['reason']}")
                log_error("Scan aborted. Review your scope file or program rules.")
                return {'success': False, 'reason': 'blocked_by_policy', 'run_id': run_id}
            
            if scope_decision['decision'] == 'UNKNOWN':
                log_warning(f"Target scope UNKNOWN: {scope_decision['reason']}")
                
                if not allow_unblock or not self.config['ALLOW_MANUAL_UNBLOCK']:
                    log_error("Scan aborted. Provide --scope-file or enable manual unblock.")
                    return {'success': False, 'reason': 'unknown_scope', 'run_id': run_id}
                
                # Manual confirmation required
                if not self._confirm_manual_override(target, scope_decision):
                    log_error("Manual override declined. Scan aborted.")
                    return {'success': False, 'reason': 'override_declined', 'run_id': run_id}
            
            log_info(f"✓ Target scope validated: {scope_decision['decision']}")
            
            # Step 2: Passive reconnaissance
            log_info("Step 2: Running passive reconnaissance...")
            recon_results = self.passive_recon.run(target)
            
            # Save recon results
            recon_file = output_path / 'recon.json'
            with open(recon_file, 'w') as f:
                json.dump(recon_results, f, indent=2)
            log_info(f"✓ Recon complete. Found {len(recon_results.get('subdomains', []))} subdomains")
            
            if mode == 'passive-only':
                log_info("Passive-only mode: Skipping active scanning")
                return {'success': True, 'run_id': run_id}
            
            # Step 3: HTTP probing
            log_info("Step 3: Probing HTTP services...")
            live_hosts = recon_results.get('live_hosts', [])
            log_info(f"✓ Found {len(live_hosts)} live hosts")
            
            # Step 4: Crawling (if safe-scan or full-scan)
            if mode in ['safe-scan', 'full-scan-with-validation']:
                log_info("Step 4: Crawling web applications...")
                crawl_results = []
                for host in live_hosts[:5]:  # Limit to first 5 hosts
                    try:
                        result = self.crawler.crawl(host)
                        crawl_results.extend(result)
                    except Exception as e:
                        log_warning(f"Crawl failed for {host}: {e}")
                
                log_info(f"✓ Crawled {len(crawl_results)} URLs")
            
            # Step 5: Safe scanning with Nuclei
            log_info("Step 5: Running safe vulnerability scans...")
            findings = []
            
            for host in live_hosts:
                # Validate each scan action
                scan_decision = self.policy_engine.validate_scanner_action(
                    action_descriptor={
                        'scanner': 'nuclei',
                        'target': host,
                        'severity': 'low,medium'
                    }
                )
                
                if scan_decision['decision'] == 'BLOCKED':
                    log_warning(f"Scan blocked for {host}: {scan_decision['reason']}")
                    continue
                
                if scan_decision['decision'] == 'REQUIRES_VALIDATION':
                    log_info(f"Scan requires AI validation for {host}")
                    # In full-scan mode, this would call Gemini
                    if mode != 'full-scan-with-validation':
                        log_warning("Skipping (not in full-scan mode)")
                        continue
                
                # Run nuclei scan
                try:
                    scan_results = self.nuclei_runner.run(host, severity=['low', 'medium'])
                    findings.extend(scan_results)
                except Exception as e:
                    log_warning(f"Nuclei scan failed for {host}: {e}")
            
            log_info(f"✓ Scan complete. Found {len(findings)} potential findings")
            
            # Step 6: AI-powered triage
            log_info("Step 6: Running AI triage on findings...")
            triaged_findings = []
            
            for finding in findings:
                try:
                    triage_result = self.triage_engine.score_finding(finding)
                    triaged_finding = {**finding, **triage_result}
                    triaged_findings.append(triaged_finding)
                    
                    # Save to database
                    save_finding(run_id, triaged_finding)
                except Exception as e:
                    log_warning(f"Triage failed for finding: {e}")
            
            # Sort by score
            triaged_findings.sort(key=lambda x: x.get('final_score', 0), reverse=True)
            
            # Save findings
            findings_file = output_path / 'findings.json'
            with open(findings_file, 'w') as f:
                json.dump(triaged_findings, f, indent=2)
            
            log_info(f"✓ Triage complete. {len(triaged_findings)} findings scored")
            
            # Step 7: Generate report
            log_info("Step 7: Generating HackerOne-ready report...")
            report_path = self.report_generator.generate(
                run_id=run_id,
                target=target,
                findings=triaged_findings,
                output_dir=output_path
            )
            
            log_info(f"✓ Report generated: {report_path}")
            
            # Summary
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            log_info(f"\n{'='*60}")
            log_info(f"Pipeline complete for {target}")
            log_info(f"Duration: {duration:.1f}s")
            log_info(f"Findings: {len(triaged_findings)}")
            log_info(f"Output: {output_path}")
            log_info(f"{'='*60}\n")
            
            return {'success': True, 'run_id': run_id, 'findings': len(triaged_findings)}
            
        except Exception as e:
            log_error(f"Pipeline failed: {e}")
            import traceback
            log_error(traceback.format_exc())
            return {'success': False, 'reason': str(e), 'run_id': run_id}
    
    def _confirm_manual_override(self, target, decision):
        """
        Require explicit manual confirmation for policy override.
        
        Args:
            target (str): Target being scanned
            decision (dict): Policy decision
        
        Returns:
            bool: True if user confirms, False otherwise
        """
        print("\n" + "="*60)
        print("⚠️  MANUAL OVERRIDE REQUIRED")
        print("="*60)
        print(f"Target: {target}")
        print(f"Reason: {decision['reason']}")
        print("\nThis target's scope could not be automatically validated.")
        print("Proceeding requires explicit confirmation that you have permission.")
        print("\nType 'I_ACCEPT_RISK' to continue, or anything else to abort:")
        print("="*60)
        
        response = input("> ").strip()
        
        if response == 'I_ACCEPT_RISK':
            log_warning(f"Manual override accepted for {target} by user")
            # Log to database for audit
            from db.storage import log_policy_decision
            log_policy_decision(
                target=target,
                action='manual_override',
                decision='ALLOWED',
                reason='User accepted risk with explicit confirmation',
                confidence=1.0
            )
            return True
        else:
            log_info("Manual override declined")
            return False
    
    def generate_report_only(self, run_id):
        """
        Generate report from existing run data.
        
        Args:
            run_id (str): Run ID to generate report for
        
        Returns:
            bool: True if successful
        """
        try:
            findings = get_run_findings(run_id)
            
            if not findings:
                log_error(f"No findings found for run {run_id}")
                return False
            
            # Get target from first finding
            target = findings[0].get('target', 'unknown')
            
            output_path = Path(self.config['OUTPUT_DIR']) / run_id
            output_path.mkdir(parents=True, exist_ok=True)
            
            report_path = self.report_generator.generate(
                run_id=run_id,
                target=target,
                findings=findings,
                output_dir=output_path
            )
            
            log_info(f"Report generated: {report_path}")
            return True
            
        except Exception as e:
            log_error(f"Report generation failed: {e}")
            return False
