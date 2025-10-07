"""
Gemini API client with retry logic and safety guardrails.

This is a thin wrapper around the Gemini API for:
- Policy validation
- Triage scoring
- Report generation assistance
"""

import json
import time
from tenacity import retry, stop_after_attempt, wait_exponential

from utils.logger import log_info, log_warning, log_error


class GeminiClient:
    """Client for interacting with Google Gemini API."""
    
    def __init__(self, config):
        """
        Initialize Gemini client.
        
        Args:
            config (dict): Configuration with GEMINI_API_KEY
        """
        self.config = config
        self.api_key = config.get('GEMINI_API_KEY')
        
        if not self.api_key:
            log_warning("Gemini API key not configured")
            self.enabled = False
        else:
            self.enabled = True
            self._init_client()
    
    def _init_client(self):
        """Initialize the Gemini API client."""
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            self.genai = genai
            log_info("Gemini client initialized")
        except ImportError:
            log_error("google-generativeai package not installed")
            log_error("Install with: pip install google-generativeai")
            self.enabled = False
        except Exception as e:
            log_error(f"Failed to initialize Gemini client: {e}")
            self.enabled = False
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def call_gemini(self, prompt, system_prompt=None, max_tokens=1000, temperature=0.3):
        """
        Call Gemini API with retry logic.
        
        Args:
            prompt (str): User prompt
            system_prompt (str): System prompt for context
            max_tokens (int): Maximum tokens in response
            temperature (float): Sampling temperature (0.0-1.0)
        
        Returns:
            str: Response text from Gemini
        
        Raises:
            Exception: If API call fails after retries
        """
        if not self.enabled:
            raise Exception("Gemini client not enabled (check API key)")
        
        try:
            # Use Gemini 1.5 Flash for fast responses
            model = self.genai.GenerativeModel('gemini-1.5-flash')
            
            # Combine system and user prompts
            full_prompt = prompt
            if system_prompt:
                full_prompt = f"{system_prompt}\n\n{prompt}"
            
            # Configure generation
            generation_config = {
                'temperature': temperature,
                'max_output_tokens': max_tokens,
            }
            
            # Call API
            log_info(f"Calling Gemini API (temp={temperature}, max_tokens={max_tokens})")
            response = model.generate_content(
                full_prompt,
                generation_config=generation_config
            )
            
            # Extract text
            if response.text:
                log_info("Gemini API call successful")
                
                # Store response if configured
                if self.config.get('STORE_LLM_RESPONSES'):
                    self._store_response(prompt, response.text)
                
                return response.text
            else:
                raise Exception("Empty response from Gemini")
            
        except Exception as e:
            log_error(f"Gemini API call failed: {e}")
            raise
    
    def validate_json_response(self, response_text):
        """
        Validate and parse JSON response from Gemini.
        
        Args:
            response_text (str): Response text
        
        Returns:
            dict: Parsed JSON or None if invalid
        """
        try:
            # Try to extract JSON from markdown code blocks
            if '```json' in response_text:
                start = response_text.find('```json') + 7
                end = response_text.find('```', start)
                response_text = response_text[start:end].strip()
            elif '```' in response_text:
                start = response_text.find('```') + 3
                end = response_text.find('```', start)
                response_text = response_text[start:end].strip()
            
            return json.loads(response_text)
        except json.JSONDecodeError as e:
            log_error(f"Failed to parse Gemini JSON response: {e}")
            log_error(f"Response: {response_text[:200]}")
            return None
    
    def _store_response(self, prompt, response):
        """
        Store LLM response for audit.
        
        Args:
            prompt (str): Input prompt
            response (str): LLM response
        """
        try:
            from db.storage import store_llm_response
            store_llm_response(prompt, response)
        except Exception as e:
            log_warning(f"Failed to store LLM response: {e}")
    
    def score_finding(self, finding_data):
        """
        Use Gemini to score and explain a security finding.
        
        Args:
            finding_data (dict): Finding details
        
        Returns:
            dict: Score and explanation
        """
        if not self.enabled:
            return {
                'llm_score': 0.5,
                'llm_explanation': 'Gemini not available',
                'confidence': 0.0
            }
        
        system_prompt = """You are a security researcher evaluating vulnerability findings.
Score the finding from 0.0 (false positive) to 1.0 (critical true positive).

Respond with JSON:
{
  "score": 0.0 to 1.0,
  "confidence": 0.0 to 1.0,
  "explanation": "brief explanation",
  "severity": "info|low|medium|high|critical",
  "is_likely_fp": true or false
}

Consider:
- Evidence quality
- Exploitability
- Impact
- Context"""
        
        user_prompt = f"""Finding:
Name: {finding_data.get('name', 'Unknown')}
Severity: {finding_data.get('severity', 'Unknown')}
Description: {finding_data.get('description', 'N/A')}
Evidence: {finding_data.get('evidence', 'N/A')[:500]}

Score this finding:"""
        
        try:
            response = self.call_gemini(
                prompt=user_prompt,
                system_prompt=system_prompt,
                max_tokens=400,
                temperature=0.2
            )
            
            result = self.validate_json_response(response)
            
            if result:
                return {
                    'llm_score': result.get('score', 0.5),
                    'llm_explanation': result.get('explanation', ''),
                    'confidence': result.get('confidence', 0.5),
                    'llm_severity': result.get('severity', 'unknown'),
                    'is_likely_fp': result.get('is_likely_fp', False)
                }
            else:
                return {
                    'llm_score': 0.5,
                    'llm_explanation': 'Failed to parse response',
                    'confidence': 0.0
                }
                
        except Exception as e:
            log_error(f"Gemini scoring failed: {e}")
            return {
                'llm_score': 0.5,
                'llm_explanation': f'Error: {e}',
                'confidence': 0.0
            }
    
    def polish_report(self, report_text):
        """
        Use Gemini to improve report language.
        
        Args:
            report_text (str): Draft report
        
        Returns:
            str: Polished report
        """
        if not self.enabled:
            return report_text
        
        system_prompt = """You are an expert security writer for bug bounty reports.
Edit and improve the report to be:
- Concise and clear
- Professional but friendly
- Focused on facts and evidence
- Suitable for HackerOne triage team

DO NOT:
- Add exploit code or instructions
- Suggest destructive actions
- Change technical accuracy
- Add speculation

Return the improved report text."""
        
        user_prompt = f"""Improve this bug report:

{report_text}"""
        
        try:
            response = self.call_gemini(
                prompt=user_prompt,
                system_prompt=system_prompt,
                max_tokens=2000,
                temperature=0.4
            )
            
            return response
            
        except Exception as e:
            log_error(f"Report polishing failed: {e}")
            return report_text
