import joblib
from sklearn.preprocessing import OrdinalEncoder, StandardScaler

# Columns used by UNSW-NB15
DROP_COLS = ["id", "srcip", "dstip", "stime", "ltime"]
CATEGORICAL_COLS = ["proto", "service", "state"]

ENCODER_PATH = "ml/anomaly/models/anomaly_encoder.pkl"
SCALER_PATH = "ml/anomaly/models/anomaly_scaler.pkl"


def preprocess_anomaly_data(df, fit=True):
    df = df.copy()

    # Remove labels if present
    for col in ["label", "attack_cat"]:
        if col in df.columns:
            df.drop(col, axis=1, inplace=True)

    # Drop unused columns
    for col in DROP_COLS:
        if col in df.columns:
            df.drop(col, axis=1, inplace=True)

    # Encode categorical
    if fit:
        encoder = OrdinalEncoder(
            handle_unknown="use_encoded_value",
            unknown_value=-1
        )
        df[CATEGORICAL_COLS] = encoder.fit_transform(df[CATEGORICAL_COLS])
        joblib.dump(encoder, ENCODER_PATH)
    else:
        encoder = joblib.load(ENCODER_PATH)
        df[CATEGORICAL_COLS] = encoder.transform(df[CATEGORICAL_COLS])

    # Scale
    if fit:
        scaler = StandardScaler()
        X = scaler.fit_transform(df)
        joblib.dump(scaler, SCALER_PATH)
    else:
        scaler = joblib.load(SCALER_PATH)
        X = scaler.transform(df)

    return X
