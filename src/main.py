#!/usr/bin/env python3
"""
Kali Bounty Scanner Plus - Main Entry Point

⚠️  LEGAL NOTICE:
This tool is for AUTHORIZED security testing only. Use only on targets where
you have EXPLICIT WRITTEN PERMISSION. Unauthorized access is illegal.

The tool will refuse to run when:
- Target scope is unknown or ambiguous
- Policy engine blocks high-risk actions
- Required confirmations are not provided

All actions are logged for audit purposes.
"""

import argparse
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from config import load_config
from orchestrator import Orchestrator
from utils.logger import setup_logger, log_info, log_error, log_warning
from db.storage import init_db


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Kali Bounty Scanner Plus - Ethical Bug Bounty Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Passive reconnaissance only
  python3 src/main.py --target example.com --mode passive-only

  # Safe scanning with scope validation
  python3 src/main.py --target example.com --mode safe-scan --scope-file scope.json

  # Full pipeline with AI validation
  python3 src/main.py --target example.com --mode full-scan-with-validation --scope-file scope.json

  # Scan multiple targets
  python3 src/main.py --targets-file targets.txt --mode safe-scan --scope-file scope.json

  # Generate report only from existing findings
  python3 src/main.py --generate-report-only --run-id <run_id>
        """
    )
    
    # Target specification
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        '--target',
        help='Single target domain or IP'
    )
    target_group.add_argument(
        '--targets-file',
        help='File containing list of targets (one per line)'
    )
    target_group.add_argument(
        '--generate-report-only',
        action='store_true',
        help='Generate report from existing run (requires --run-id)'
    )
    
    # Scan mode
    parser.add_argument(
        '--mode',
        choices=['passive-only', 'safe-scan', 'full-scan-with-validation'],
        default='safe-scan',
        help='Scan mode (default: safe-scan)'
    )
    
    # Scope file
    parser.add_argument(
        '--scope-file',
        help='JSON file defining in-scope targets (required for validation)'
    )
    
    # Manual unblock
    parser.add_argument(
        '--allow-unblock',
        action='store_true',
        help='Allow manual unblocking of policy-blocked actions (requires confirmation)'
    )
    
    # Report generation
    parser.add_argument(
        '--run-id',
        help='Run ID for report generation'
    )
    
    # Output directory
    parser.add_argument(
        '--output-dir',
        help='Custom output directory (default: from config)'
    )
    
    return parser.parse_args()


def print_banner():
    """Print tool banner."""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        Kali Bounty Scanner Plus v1.0                      ║
║        AI-Driven Ethical Bug Bounty Toolkit               ║
║                                                           ║
║  ⚠️  USE ONLY ON AUTHORIZED TARGETS                       ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Main entry point."""
    print_banner()
    
    args = parse_args()
    
    # Load configuration
    try:
        config = load_config()
        log_info("Configuration loaded successfully")
    except Exception as e:
        log_error(f"Failed to load configuration: {e}")
        sys.exit(1)
    
    # Setup logging
    setup_logger(config)
    
    # Initialize database
    try:
        init_db()
        log_info("Database initialized")
    except Exception as e:
        log_error(f"Failed to initialize database: {e}")
        sys.exit(1)
    
    # Validate Gemini API key
    if not config.get('GEMINI_API_KEY'):
        log_error("GEMINI_API_KEY not found in .env file")
        log_error("Get your API key from: https://makersuite.google.com/app/apikey")
        sys.exit(1)
    
    # Create orchestrator
    orchestrator = Orchestrator(config)
    
    # Handle report-only mode
    if args.generate_report_only:
        if not args.run_id:
            log_error("--run-id required for --generate-report-only")
            sys.exit(1)
        
        log_info(f"Generating report for run: {args.run_id}")
        success = orchestrator.generate_report_only(args.run_id)
        sys.exit(0 if success else 1)
    
    # Get targets
    targets = []
    if args.target:
        targets = [args.target]
    elif args.targets_file:
        try:
            with open(args.targets_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            log_error(f"Failed to read targets file: {e}")
            sys.exit(1)
    
    if not targets:
        log_error("No targets specified")
        sys.exit(1)
    
    log_info(f"Loaded {len(targets)} target(s)")
    log_info(f"Scan mode: {args.mode}")
    
    # Run orchestrator for each target
    results = []
    for target in targets:
        log_info(f"\n{'='*60}")
        log_info(f"Processing target: {target}")
        log_info(f"{'='*60}\n")
        
        result = orchestrator.run_pipeline(
            target=target,
            mode=args.mode,
            scope_file=args.scope_file,
            allow_unblock=args.allow_unblock,
            output_dir=args.output_dir
        )
        
        results.append({
            'target': target,
            'success': result['success'],
            'run_id': result.get('run_id')
        })
    
    # Print summary
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    
    for result in results:
        status = "✓ SUCCESS" if result['success'] else "✗ FAILED"
        print(f"{status} - {result['target']}")
        if result.get('run_id'):
            print(f"  Run ID: {result['run_id']}")
    
    print("="*60 + "\n")
    
    # Exit with appropriate code
    all_success = all(r['success'] for r in results)
    sys.exit(0 if all_success else 1)


if __name__ == '__main__':
    main()
