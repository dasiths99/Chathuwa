"""
Kaggle training script for Web Access Monitor.

Run this in a Kaggle notebook to train the RandomForest attack prediction model
and export the .pkl files expected by web_access.py.

Expected output files:
  - attack_prediction_model.pkl
  - label_encoders.pkl
  - target_encoder.pkl
  - complete_prediction_pipeline.pkl
  - attack_detection_pipeline.pkl

After downloading these files from Kaggle, place them in this project folder:
  restricted/
"""

import os
import glob
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


# Change this if your Kaggle dataset CSV has a different name/path.
# The auto-detect fallback searches /kaggle/input for a CSV containing "web-access".
DATASET_PATH = "/kaggle/input/web-access-dataset/web-access-anolamy-detection_dataset.csv"
OUTPUT_DIR = "/kaggle/working"
UNKNOWN_TOKEN = "!!!UNKNOWN!!!"


FEATURES = [
    "time",
    "end_time",
    "user_id",
    "source_ip",
    "domain",
    "domain_type",
    "access_type",
    "request_type",
    "protocol",
    "vpn_usage",
    "tor_usage",
    "dns_encryption",
    "user_role",
    "user_activity_type",
    "recent_web_access_attempts",
    "status",
    "attack_risk_level",
]

TARGET = "attack_prediction"

CATEGORICAL_COLUMNS = [
    "user_id",
    "source_ip",
    "domain",
    "domain_type",
    "access_type",
    "request_type",
    "protocol",
    "user_role",
    "user_activity_type",
    "status",
    "attack_risk_level",
]


def find_dataset_csv():
    if os.path.exists(DATASET_PATH):
        return DATASET_PATH

    candidates = glob.glob("/kaggle/input/**/*.csv", recursive=True)
    web_candidates = [
        path for path in candidates
        if "web" in os.path.basename(path).lower()
        and "access" in os.path.basename(path).lower()
    ]

    if web_candidates:
        return web_candidates[0]

    if candidates:
        print("No web-access CSV name found. Using first CSV found:")
        return candidates[0]

    raise FileNotFoundError("No CSV dataset found under /kaggle/input")


def time_to_minutes(value):
    if pd.isna(value):
        return 0

    if isinstance(value, (int, float, np.integer, np.floating)):
        return int(value)

    try:
        value = str(value).strip()
        parsed = pd.to_datetime(value, format="%H:%M:%S", errors="coerce")
        if pd.isna(parsed):
            parsed = pd.to_datetime(value, format="%H:%M", errors="coerce")
        if pd.isna(parsed):
            return 0
        return int(parsed.hour * 60 + parsed.minute)
    except Exception:
        return 0


def fit_label_encoder_with_unknown(values):
    values = values.astype(str).fillna(UNKNOWN_TOKEN)
    values = pd.concat([pd.Series([UNKNOWN_TOKEN]), values], ignore_index=True)
    encoder = LabelEncoder()
    encoder.fit(values)
    return encoder


def transform_with_unknown(values, encoder):
    values = values.astype(str).fillna(UNKNOWN_TOKEN)
    known = set(encoder.classes_)
    values = values.where(values.isin(known), UNKNOWN_TOKEN)
    return encoder.transform(values)


def prepare_data(data):
    missing = [col for col in FEATURES + [TARGET] if col not in data.columns]
    if missing:
        raise ValueError(f"Dataset is missing required columns: {missing}")

    data = data[FEATURES + [TARGET]].dropna().copy()

    X = data[FEATURES].copy()
    y = data[TARGET].astype(str)

    X["time"] = X["time"].apply(time_to_minutes)
    X["end_time"] = X["end_time"].apply(time_to_minutes)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y if y.nunique() > 1 else None,
    )

    label_encoders = {}
    for col in CATEGORICAL_COLUMNS:
        encoder = fit_label_encoder_with_unknown(X_train[col])
        label_encoders[col] = encoder
        X_train[col] = transform_with_unknown(X_train[col], encoder)
        X_test[col] = transform_with_unknown(X_test[col], encoder)

    for col in FEATURES:
        X_train[col] = pd.to_numeric(X_train[col], errors="coerce").fillna(0)
        X_test[col] = pd.to_numeric(X_test[col], errors="coerce").fillna(0)

    target_encoder = LabelEncoder()
    y_train_encoded = target_encoder.fit_transform(y_train)
    y_test_encoded = target_encoder.transform(y_test)

    return X_train, X_test, y_train, y_test, y_train_encoded, y_test_encoded, label_encoders, target_encoder


def train_model(X_train, y_train_encoded):
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train_encoded)
    return model


def save_artifacts(model, label_encoders, target_encoder, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    pipeline = {
        "model": model,
        "label_encoders": label_encoders,
        "target_encoder": target_encoder,
        "feature_names": FEATURES,
        "target": TARGET,
        "unknown_token": UNKNOWN_TOKEN,
    }

    joblib.dump(model, os.path.join(output_dir, "attack_prediction_model.pkl"))
    joblib.dump(label_encoders, os.path.join(output_dir, "label_encoders.pkl"))
    joblib.dump(target_encoder, os.path.join(output_dir, "target_encoder.pkl"))
    joblib.dump(pipeline, os.path.join(output_dir, "complete_prediction_pipeline.pkl"))

    # web_access.py checks this name first, so save the same pipeline here too.
    joblib.dump(pipeline, os.path.join(output_dir, "attack_detection_pipeline.pkl"))


def main():
    dataset_csv = find_dataset_csv()
    print(f"Loading dataset: {dataset_csv}")

    data = pd.read_csv(dataset_csv)
    print(f"Dataset shape: {data.shape}")
    print(f"Target classes: {sorted(data[TARGET].dropna().astype(str).unique())}")

    (
        X_train,
        X_test,
        y_train,
        y_test,
        y_train_encoded,
        y_test_encoded,
        label_encoders,
        target_encoder,
    ) = prepare_data(data)

    print(f"Training rows: {len(X_train)}")
    print(f"Testing rows: {len(X_test)}")

    model = train_model(X_train, y_train_encoded)

    y_pred = model.predict(X_test)
    y_pred_labels = target_encoder.inverse_transform(y_pred)

    accuracy = accuracy_score(y_test_encoded, y_pred)
    print(f"\nAccuracy: {accuracy * 100:.2f}%")
    print("\nClassification report:")
    print(classification_report(y_test_encoded, y_pred, target_names=target_encoder.classes_))

    print("\nConfusion matrix:")
    print(confusion_matrix(y_test_encoded, y_pred))

    feature_importance = pd.DataFrame({
        "feature": FEATURES,
        "importance": model.feature_importances_,
    }).sort_values("importance", ascending=False)
    print("\nTop feature importances:")
    print(feature_importance.head(15).to_string(index=False))

    print("\nSample predictions:")
    sample = pd.DataFrame({
        "actual": y_test.reset_index(drop=True).head(10),
        "predicted": pd.Series(y_pred_labels).head(10),
    })
    print(sample.to_string(index=False))

    save_artifacts(model, label_encoders, target_encoder, OUTPUT_DIR)

    print("\nSaved files to /kaggle/working:")
    for name in [
        "attack_detection_pipeline.pkl",
        "attack_prediction_model.pkl",
        "complete_prediction_pipeline.pkl",
        "label_encoders.pkl",
        "target_encoder.pkl",
    ]:
        print(f"  - {name}")

    print("\nDownload these .pkl files and place them in your project restricted/ folder.")


if __name__ == "__main__":
    main()
