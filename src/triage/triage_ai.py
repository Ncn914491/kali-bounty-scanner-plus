"""AI-powered triage engine combining ML and LLM scoring."""

import pickle
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from integrations.gemini_client import GeminiClient
from utils.logger import log_info, log_warning, log_error


class TriageEngine:
    """Triage engine with ML + LLM fusion scoring."""
    
    def __init__(self, config):
        """
        Initialize triage engine.
        
        Args:
            config (dict): Configuration dictionary
        """
        self.config = config
        self.gemini_client = GeminiClient(config)
        self.ml_model = self._load_ml_model()
        self.ml_weight = config['ML_WEIGHT']
        self.llm_weight = config['LLM_WEIGHT']
    
    def _load_ml_model(self):
        """Load trained ML model or create default."""
        model_path = Path('models/triage_model.pkl')
        
        if model_path.exists():
            try:
                with open(model_path, 'rb') as f:
                    model = pickle.load(f)
                log_info("Loaded trained triage model")
                return model
            except Exception as e:
                log_warning(f"Failed to load model: {e}")
        
        # Return untrained pipeline as fallback
        log_info("Using default untrained model")
        return Pipeline([
            ('tfidf', TfidfVectorizer(max_features=100)),
            ('classifier', LogisticRegression())
        ])
    
    def score_finding(self, finding):
        """
        Score a finding using ML + LLM fusion.
        
        Args:
            finding (dict): Finding data
        
        Returns:
            dict: Triage result with scores and explanation
        """
        # Extract text features for ML
        text_features = self._extract_text_features(finding)
        
        # ML scoring
        ml_score = self._ml_score(text_features)
        
        # LLM scoring (if available)
        llm_result = self.gemini_client.score_finding(finding)
        llm_score = llm_result.get('llm_score', 0.5)
        llm_explanation = llm_result.get('llm_explanation', '')
        confidence = llm_result.get('confidence', 0.5)
        
        # Fusion score (weighted average)
        final_score = (self.ml_weight * ml_score) + (self.llm_weight * llm_score)
        
        # Determine if likely false positive
        is_likely_fp = llm_result.get('is_likely_fp', False) or final_score < 0.3
        
        result = {
            'ml_score': ml_score,
            'llm_score': llm_score,
            'final_score': final_score,
            'confidence': confidence,
            'explanation': llm_explanation,
            'is_false_positive': is_likely_fp,
            'severity_adjusted': self._adjust_severity(finding, final_score)
        }
        
        log_info(f"Triaged finding: {finding.get('name', 'Unknown')} - Score: {final_score:.2f}")
        
        return result
    
    def _extract_text_features(self, finding):
        """
        Extract text features from finding for ML.
        
        Args:
            finding (dict): Finding data
        
        Returns:
            str: Combined text features
        """
        parts = [
            finding.get('name', ''),
            finding.get('description', ''),
            finding.get('severity', ''),
            str(finding.get('evidence', {}))
        ]
        
        return ' '.join(parts)
    
    def _ml_score(self, text_features):
        """
        Score using ML model.
        
        Args:
            text_features (str): Text features
        
        Returns:
            float: ML score (0.0-1.0)
        """
        try:
            # Check if model is trained
            if hasattr(self.ml_model, 'classes_'):
                # Predict probability
                proba = self.ml_model.predict_proba([text_features])[0]
                # Return probability of positive class
                return proba[1] if len(proba) > 1 else 0.5
            else:
                # Model not trained, return neutral score
                return 0.5
        except Exception as e:
            log_warning(f"ML scoring failed: {e}")
            return 0.5
    
    def _adjust_severity(self, finding, score):
        """
        Adjust severity based on triage score.
        
        Args:
            finding (dict): Finding data
            score (float): Triage score
        
        Returns:
            str: Adjusted severity
        """
        original_severity = finding.get('severity', 'unknown').lower()
        
        # Downgrade if low score
        if score < 0.3:
            return 'info'
        elif score < 0.5:
            if original_severity in ['high', 'critical']:
                return 'medium'
            return original_severity
        elif score > 0.8:
            # Upgrade if high confidence
            if original_severity == 'medium':
                return 'high'
            return original_severity
        
        return original_severity
