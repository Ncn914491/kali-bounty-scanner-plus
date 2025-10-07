"""Database storage utilities."""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from contextlib import contextmanager

from utils.logger import log_info, log_error


def get_db_path():
    """Get database path from config."""
    from config import get_config_value
    db_path = get_config_value('DB_PATH', './db/scanner.db')
    
    # Ensure directory exists
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    
    return db_path


@contextmanager
def get_db_connection():
    """Context manager for database connections."""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


def init_db():
    """Initialize database with schema."""
    schema_path = Path(__file__).parent / 'schema.sql'
    
    if not schema_path.exists():
        log_error("Database schema file not found")
        return False
    
    try:
        with open(schema_path, 'r') as f:
            schema = f.read()
        
        with get_db_connection() as conn:
            conn.executescript(schema)
        
        log_info("Database initialized successfully")
        return True
        
    except Exception as e:
        log_error(f"Failed to initialize database: {e}")
        return False


def save_run(run_id, target, mode, output_dir):
    """
    Save a new scan run.
    
    Args:
        run_id (str): Unique run identifier
        target (str): Target domain/IP
        mode (str): Scan mode
        output_dir (str): Output directory path
    """
    try:
        with get_db_connection() as conn:
            conn.execute(
                """INSERT INTO runs (run_id, target, mode, output_dir)
                   VALUES (?, ?, ?, ?)""",
                (run_id, target, mode, output_dir)
            )
        log_info(f"Run saved: {run_id}")
    except Exception as e:
        log_error(f"Failed to save run: {e}")


def save_finding(run_id, finding):
    """
    Save a finding to database.
    
    Args:
        run_id (str): Run identifier
        finding (dict): Finding data
    """
    try:
        with get_db_connection() as conn:
            conn.execute(
                """INSERT INTO findings 
                   (run_id, target, name, severity, description, evidence,
                    ml_score, llm_score, final_score, confidence, is_false_positive)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    finding.get('target', ''),
                    finding.get('name', ''),
                    finding.get('severity', ''),
                    finding.get('description', ''),
                    json.dumps(finding.get('evidence', {})),
                    finding.get('ml_score', 0.0),
                    finding.get('llm_score', 0.0),
                    finding.get('final_score', 0.0),
                    finding.get('confidence', 0.0),
                    finding.get('is_false_positive', False)
                )
            )
    except Exception as e:
        log_error(f"Failed to save finding: {e}")


def get_run_findings(run_id):
    """
    Get all findings for a run.
    
    Args:
        run_id (str): Run identifier
    
    Returns:
        list: List of finding dictionaries
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.execute(
                """SELECT * FROM findings WHERE run_id = ?
                   ORDER BY final_score DESC""",
                (run_id,)
            )
            rows = cursor.fetchall()
            
            findings = []
            for row in rows:
                finding = dict(row)
                # Parse JSON evidence
                if finding.get('evidence'):
                    try:
                        finding['evidence'] = json.loads(finding['evidence'])
                    except:
                        pass
                findings.append(finding)
            
            return findings
    except Exception as e:
        log_error(f"Failed to get findings: {e}")
        return []


def log_policy_decision(target, action, decision, reason, confidence):
    """
    Log a policy decision for audit.
    
    Args:
        target (str): Target
        action (str): Action type
        decision (str): Decision (ALLOWED/BLOCKED/UNKNOWN)
        reason (str): Reason for decision
        confidence (float): Confidence score
    """
    try:
        with get_db_connection() as conn:
            conn.execute(
                """INSERT INTO policy_decisions 
                   (target, action, decision, reason, confidence)
                   VALUES (?, ?, ?, ?, ?)""",
                (target, action, decision, reason, confidence)
            )
    except Exception as e:
        log_error(f"Failed to log policy decision: {e}")


def store_llm_response(prompt, response):
    """
    Store LLM response for audit.
    
    Args:
        prompt (str): Input prompt
        response (str): LLM response
    """
    try:
        with get_db_connection() as conn:
            conn.execute(
                """INSERT INTO llm_responses (prompt, response)
                   VALUES (?, ?)""",
                (prompt[:1000], response[:5000])  # Truncate for storage
            )
    except Exception as e:
        log_error(f"Failed to store LLM response: {e}")


def update_run_status(run_id, status, findings_count=None):
    """
    Update run status.
    
    Args:
        run_id (str): Run identifier
        status (str): Status (running/completed/failed)
        findings_count (int): Number of findings
    """
    try:
        with get_db_connection() as conn:
            if findings_count is not None:
                conn.execute(
                    """UPDATE runs 
                       SET status = ?, end_time = ?, findings_count = ?
                       WHERE run_id = ?""",
                    (status, datetime.now(), findings_count, run_id)
                )
            else:
                conn.execute(
                    """UPDATE runs 
                       SET status = ?, end_time = ?
                       WHERE run_id = ?""",
                    (status, datetime.now(), run_id)
                )
    except Exception as e:
        log_error(f"Failed to update run status: {e}")
