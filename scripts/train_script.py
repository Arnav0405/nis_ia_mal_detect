import os
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from collections import Counter
import warnings

warnings.filterwarnings('ignore')

# Feature extraction function
def extract_features(file_path):
    """
    Extract byte frequency features from .bytes file
    Returns a 256-dimensional feature vector representing byte frequency distribution
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read().strip().split()
            bytes_list = [b for b in content if b != '??' and len(b) == 2]
            bytes_int = [int(b, 16) for b in bytes_list]
            byte_counts = Counter(bytes_int)
            feature_vector = [byte_counts.get(i, 0) / max(1, len(bytes_int)) for i in range(256)]
            return feature_vector
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return [0] * 256


def load_and_extract_features(csv_path, data_dir):
    """
    Load labels from CSV and extract features for all files
    
    Args:
        csv_path: Path to trainLabels.csv
        data_dir: Directory containing .bytes files
    
    Returns:
        X: Feature matrix (num_samples, 256)
        y: Class labels
        file_ids: List of file IDs
    """
    print("Loading labels from CSV...")
    df = pd.read_csv(csv_path)
    
    X = []
    y = []
    file_ids = []
    
    print(f"Extracting features from {len(df)} files...")
    for idx, row in df.iterrows():
        file_id = row['Id']
        label = row['Class']
        
        file_path = os.path.join(data_dir, f"{file_id}.bytes")
        
        if os.path.exists(file_path):
            features = extract_features(file_path)
            X.append(features)
            y.append(label - 1)  # Convert to 0-indexed class labels
            file_ids.append(file_id)
            
            if (idx + 1) % 100 == 0:
                print(f"  Processed {idx + 1}/{len(df)} files")
        else:
            print(f"  Warning: File not found: {file_path}")
    
    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int32)
    
    return X, y, file_ids


def print_class_distribution(y, split_name=""):
    """Print the distribution of classes"""
    unique, counts = np.unique(y, return_counts=True)
    print(f"\n{split_name} Class Distribution:")
    print("-" * 50)
    for cls, count in zip(unique, counts):
        percentage = (count / len(y)) * 100
        print(f"  Class {cls + 1}: {count:5d} samples ({percentage:5.2f}%)")
    print("-" * 50)


def train_xgboost_model(X_train, y_train, X_test, y_test):
    """
    Train XGBoost model with GPU acceleration for unbalanced dataset
    
    Args:
        X_train, y_train: Training data and labels
        X_test, y_test: Test data and labels
    
    Returns:
        model: Trained XGBoost model
    """
    
    # Calculate scale_pos_weight to handle class imbalance
    # For multiclass, we'll use class weights based on inverse frequency
    class_counts = np.bincount(y_train)
    num_classes = len(class_counts)
    
    print("\nTraining Parameters for Handling Imbalanced Dataset:")
    print("-" * 50)
    print(f"Number of classes: {num_classes}")
    print(f"Class weights (inverse frequency):")
    
    # Calculate weights for each class
    class_weights = len(y_train) / (num_classes * class_counts)
    for cls_idx, weight in enumerate(class_weights):
        print(f"  Class {cls_idx + 1}: {weight:.4f}")
    
    # Create DMatrix for training and evaluation
    print("\nCreating DMatrix for GPU training...")
    dtrain = xgb.DMatrix(X_train, label=y_train)
    dtest = xgb.DMatrix(X_test, label=y_test)
    
    # XGBoost parameters optimized for GPU and unbalanced data
    params = {
        'max_depth': 8,
        'learning_rate': 0.1,
        'objective': 'multi:softmax',  # Multiclass classification
        'num_class': num_classes,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'min_child_weight': 1,
        'gamma': 0.5,
        'tree_method': 'gpu_hist',  # Use GPU for training
        'gpu_id': 0,  # Use first GPU
        'scale_pos_weight': 1.0,  # Not directly used for multiclass, but included
        'eval_metric': 'mlogloss',  # Log loss for multiclass
        'seed': 42,
    }
    
    print("\nXGBoost Parameters:")
    print("-" * 50)
    for key, value in params.items():
        print(f"  {key}: {value}")
    
    # Training with early stopping
    evals = [(dtrain, 'train'), (dtest, 'test')]
    evals_result = {}
    
    print("\nTraining XGBoost model with GPU acceleration...")
    print("-" * 50)
    
    model = xgb.train(
        params,
        dtrain,
        num_boost_round=200,
        evals=evals,
        evals_result=evals_result,
        early_stopping_rounds=20,
        verbose_eval=10
    )
    
    return model, evals_result


def evaluate_model(model, X_test, y_test):
    """
    Evaluate the trained model
    
    Args:
        model: Trained XGBoost model
        X_test, y_test: Test data and labels
    """
    print("\n" + "=" * 70)
    print("MODEL EVALUATION")
    print("=" * 70)
    
    dtest = xgb.DMatrix(X_test, label=y_test)
    y_pred = model.predict(dtest).astype(np.int32)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    f1_weighted = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    f1_macro = f1_score(y_test, y_pred, average='macro', zero_division=0)
    
    print(f"\nOverall Metrics:")
    print("-" * 70)
    print(f"  Accuracy:           {accuracy:.4f}")
    print(f"  F1-Score (Weighted): {f1_weighted:.4f}")
    print(f"  F1-Score (Macro):    {f1_macro:.4f}")
    
    print(f"\nConfusion Matrix:")
    print("-" * 70)
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    
    print(f"\nClassification Report:")
    print("-" * 70)
    print(classification_report(y_test, y_pred, digits=4, zero_division=0))
    
    print("=" * 70)
    
    return {
        'accuracy': accuracy,
        'f1_weighted': f1_weighted,
        'f1_macro': f1_macro,
        'confusion_matrix': cm
    }


def main():
    """Main training pipeline"""
    
    print("=" * 70)
    print("XGBoost Malware Classification Model Training")
    print("GPU-Accelerated Training for Imbalanced Dataset")
    print("=" * 70)
    
    # Paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(base_dir)
    csv_path = os.path.join(project_dir, 'data', 'trainLabels.csv')
    data_dir = os.path.join(project_dir, 'data')
    model_save_path = os.path.join(project_dir, 'saved_w.model')
    
    # Load and extract features
    X, y, file_ids = load_and_extract_features(csv_path, data_dir)
    
    print(f"\nDataset Summary:")
    print(f"  Total samples: {len(X)}")
    print(f"  Feature dimension: {X.shape[1]}")
    print_class_distribution(y, "Original Dataset")
    
    # Stratified train-test split for imbalanced dataset
    # StratifiedShuffleSplit maintains class distribution in both train and test sets
    print("\nPerforming Stratified Train-Test Split (80-20)...")
    print("-" * 50)
    
    sss = StratifiedShuffleSplit(
        n_splits=1,
        test_size=0.2,
        random_state=42
    )
    
    for train_idx, test_idx in sss.split(X, y):
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]
    
    print_class_distribution(y_train, "Training Set")
    print_class_distribution(y_test, "Test Set")
    
    # Train model
    model, evals_result = train_xgboost_model(X_train, y_train, X_test, y_test)
    
    # Evaluate model
    metrics = evaluate_model(model, X_test, y_test)
    
    # Save model
    print(f"\nSaving model to: {model_save_path}")
    model.save_model(model_save_path)
    print(f"Model saved successfully!")
    
    print("\n" + "=" * 70)
    print("Training Complete!")
    print("=" * 70)
    
    return model, metrics


if __name__ == "__main__":
    try:
        model, metrics = main()
    except Exception as e:
        print(f"\nError during training: {e}")
        import traceback
        traceback.print_exc()
