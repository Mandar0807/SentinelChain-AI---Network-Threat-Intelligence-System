import pandas as pd
import numpy as np
import joblib
import os
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, confusion_matrix)

DATASET_PATH = "data/dataset.csv"
MODEL_PATH   = "models/threat_model.pkl"
FEATURE_PATH = "models/feature_names.pkl"


def load_dataset():
    """Load the prepared dataset and split into features and labels."""
    print("\n[1/5] Loading dataset...")
    df = pd.read_csv(DATASET_PATH)

    print(f"      Shape        : {df.shape}")
    print(f"      Phishing (1) : {df['label'].sum()}")
    print(f"      Safe (0)     : {(df['label'] == 0).sum()}")

    # Separate features from label
    X = df.drop(columns=["label"])
    y = df["label"]

    feature_names = list(X.columns)
    print(f"      Features     : {len(feature_names)}")
    return X, y, feature_names


def train_model(X, y):
    """Split data, train Decision Tree, return model and test split."""
    print("\n[2/5] Splitting data 80/20 train/test...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y          # ensures balanced split
    )
    print(f"      Training set : {len(X_train)} rows")
    print(f"      Test set     : {len(X_test)} rows")

    print("\n[3/5] Training Decision Tree classifier...")
    model = DecisionTreeClassifier(
        max_depth=5,         # keeps tree explainable, prevents overfitting
        min_samples_split=10,
        min_samples_leaf=5,
        random_state=42
    )
    model.fit(X_train, y_train)
    print(f"      Training complete.")
    print(f"      Tree depth   : {model.get_depth()}")
    print(f"      Tree leaves  : {model.get_n_leaves()}")

    return model, X_test, y_test


def evaluate_model(model, X_test, y_test):
    """Evaluate model on test set and print full report."""
    print("\n[4/5] Evaluating model on test set...")
    y_pred = model.predict(X_test)

    accuracy  = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall    = recall_score(y_test, y_pred)
    f1        = f1_score(y_test, y_pred)
    cm        = confusion_matrix(y_test, y_pred)

    print(f"\n{'=' * 50}")
    print(f"  MODEL EVALUATION REPORT")
    print(f"{'=' * 50}")
    print(f"  Accuracy   : {accuracy  * 100:.2f}%")
    print(f"  Precision  : {precision * 100:.2f}%")
    print(f"  Recall     : {recall    * 100:.2f}%")
    print(f"  F1 Score   : {f1        * 100:.2f}%")
    print(f"\n  Confusion Matrix:")
    print(f"  ┌─────────────────────────────┐")
    print(f"  │           Predicted          │")
    print(f"  │        Safe    Phishing      │")
    print(f"  │ Safe    {cm[0][0]:<6}  {cm[0][1]:<6}        │")
    print(f"  │ Phish   {cm[1][0]:<6}  {cm[1][1]:<6}        │")
    print(f"  └─────────────────────────────┘")
    print(f"\n  True Negatives  (Safe → Safe)      : {cm[0][0]}")
    print(f"  False Positives (Safe → Phishing)  : {cm[0][1]}")
    print(f"  False Negatives (Phish → Safe)     : {cm[1][0]}")
    print(f"  True Positives  (Phish → Phishing) : {cm[1][1]}")
    print(f"{'=' * 50}")

    return accuracy, f1


def show_feature_importance(model, feature_names):
    """Print which features the model relies on most."""
    print(f"\n  Top Features by Importance:")
    print(f"  {'Feature':<35} Importance")
    print(f"  {'-' * 50}")

    importances = model.feature_importances_
    indices     = np.argsort(importances)[::-1]

    for i in indices:
        if importances[i] > 0.01:
            bar = "█" * int(importances[i] * 40)
            print(f"  {feature_names[i]:<35} "
                  f"{importances[i]:.4f}  {bar}")


def save_model(model, feature_names):
    """Save trained model and feature names to disk."""
    print(f"\n[5/5] Saving model...")
    os.makedirs("models", exist_ok=True)
    joblib.dump(model,         MODEL_PATH)
    joblib.dump(feature_names, FEATURE_PATH)
    print(f"      Model saved   : {MODEL_PATH}")
    print(f"      Features saved: {FEATURE_PATH}")


def load_trained_model():
    """Load the saved model and feature names for prediction."""
    model         = joblib.load(MODEL_PATH)
    feature_names = joblib.load(FEATURE_PATH)
    return model, feature_names


def predict(url_features: dict) -> dict:
    """
    Takes a feature dictionary from url_analyser.py
    and returns a prediction result.
    This is the function called by pre_check.py.
    """
    model, feature_names = load_trained_model()

    # Build feature vector in exact same order as training
    feature_vector = [url_features.get(f, 0) for f in feature_names]
    X = pd.DataFrame([feature_vector], columns=feature_names)

    # Predict class and probability
    prediction   = model.predict(X)[0]
    probability  = model.predict_proba(X)[0]

    confidence_phishing = round(probability[1] * 100, 1)
    confidence_safe     = round(probability[0] * 100, 1)

    # Map to verdict
    if prediction == 1:
        verdict    = "MALICIOUS"
        confidence = confidence_phishing
    else:
        if confidence_safe < 70:
            verdict    = "SUSPICIOUS"
            confidence = round(100 - confidence_safe, 1)
        else:
            verdict    = "SAFE"
            confidence = confidence_safe

    return {
        "prediction"  : int(prediction),
        "verdict"     : verdict,
        "confidence"  : confidence,
        "phishing_pct": confidence_phishing,
        "safe_pct"    : confidence_safe,
    }


def main():
    print("=" * 50)
    print("  MODEL TRAINING PIPELINE")
    print("=" * 50)

    # Train
    X, y, feature_names = load_dataset()
    model, X_test, y_test = train_model(X, y)

    # Evaluate
    accuracy, f1 = evaluate_model(model, X_test, y_test)
    show_feature_importance(model, feature_names)

    # Save
    save_model(model, feature_names)

    # Quick sanity check
    print(f"\n{'=' * 50}")
    if accuracy >= 0.90:
        print(f"  RESULT: Model accuracy {accuracy*100:.1f}% — GOOD")
    elif accuracy >= 0.80:
        print(f"  RESULT: Model accuracy {accuracy*100:.1f}% — ACCEPTABLE")
    else:
        print(f"  RESULT: Model accuracy {accuracy*100:.1f}% — NEEDS IMPROVEMENT")
        print(f"  Try increasing MAX_PHISHING/MAX_SAFE in prepare_data.py")
    print(f"  F1 Score: {f1*100:.1f}%")
    print(f"{'=' * 50}")
    print(f"\n  model.py training COMPLETE.")
    print(f"  threat_model.pkl is ready for predictions.")


if __name__ == "__main__":
    main()