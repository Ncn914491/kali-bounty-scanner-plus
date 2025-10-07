"""Train triage ML model on labeled data."""

import json
import pickle
import argparse
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score


def load_training_data(data_file):
    """
    Load labeled training data.
    
    Args:
        data_file (str): Path to JSON file with labeled examples
    
    Returns:
        tuple: (texts, labels)
    """
    with open(data_file, 'r') as f:
        data = json.load(f)
    
    texts = []
    labels = []
    
    for example in data:
        # Combine text features
        text = ' '.join([
            example.get('name', ''),
            example.get('description', ''),
            example.get('severity', ''),
            str(example.get('evidence', {}))
        ])
        
        texts.append(text)
        labels.append(example.get('label', 0))  # 0=FP, 1=TP
    
    return texts, labels


def train_model(texts, labels):
    """
    Train triage model.
    
    Args:
        texts (list): List of text features
        labels (list): List of labels (0=FP, 1=TP)
    
    Returns:
        Pipeline: Trained model
    """
    # Create pipeline
    model = Pipeline([
        ('tfidf', TfidfVectorizer(max_features=100, ngram_range=(1, 2))),
        ('classifier', LogisticRegression(max_iter=1000, class_weight='balanced'))
    ])
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )
    
    # Train
    print(f"Training on {len(X_train)} examples...")
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\nAccuracy: {accuracy:.3f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['False Positive', 'True Positive']))
    
    return model


def save_model(model, output_path):
    """
    Save trained model.
    
    Args:
        model: Trained model
        output_path (str): Output file path
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'wb') as f:
        pickle.dump(model, f)
    
    print(f"\nModel saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description='Train triage ML model')
    parser.add_argument('--data', default='src/triage/sample_data/labeled_examples.json',
                       help='Path to labeled training data')
    parser.add_argument('--output', default='models/triage_model.pkl',
                       help='Output model path')
    
    args = parser.parse_args()
    
    # Load data
    print(f"Loading training data from {args.data}...")
    texts, labels = load_training_data(args.data)
    print(f"Loaded {len(texts)} examples")
    
    # Train
    model = train_model(texts, labels)
    
    # Save
    save_model(model, args.output)


if __name__ == '__main__':
    main()
