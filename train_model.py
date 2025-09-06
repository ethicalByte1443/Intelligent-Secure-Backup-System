# -----------------------------
# Train context classification model
# -----------------------------
def train_context_model(samples, labels):
    """
    Train a toy ML model (Logistic Regression) for context detection.
    samples: list of strings
    labels: list of 0/1 (0=non-sensitive, 1=sensitive)
    Saves model to data/context_model.joblib
    """
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
    except ImportError:
        raise ImportError("scikit-learn is required to train the context model")

    import os
    import joblib

    os.makedirs("data", exist_ok=True)
    model_path = os.path.join("data", "context_model.joblib")

    # TF-IDF vectorizer
    vec = TfidfVectorizer(ngram_range=(1, 2), max_features=5000)
    X = vec.fit_transform(samples)

    # Logistic Regression classifier
    clf = LogisticRegression(max_iter=1000)
    clf.fit(X, labels)

    # Save both vectorizer and classifier
    joblib.dump((vec, clf), model_path)
    print(f"✅ Context model trained & saved at {model_path}")

# toy samples
sensitive = [
  "employee salary details confidential bank account number 1234567890",
  "payroll report contains account number and ifsc",
  "passport number A1234567 found in this file",
  "user login credentials: username admin, password qwerty123",
  "credit card statement: 4111111111111111 exp 12/25 cvv 123",
  "medical record of patient includes diagnosis and prescription",
  "tax return form containing PAN ABCDE1234F",
  "salary slip of employee with gross pay and deductions",
  "internal document with API keys and access tokens",
  "SSN: 123-45-6789 detected in HR file"
]
non = [
  "meeting notes about project timeline and tasks",
  "readme file with instructions how to run the app",
  "shopping list apples bananas milk",
  "conference schedule for keynote speakers and sessions",
  "changelog describing bug fixes and new features",
  "travel itinerary for vacation including flights and hotels",
  "user manual describing how to install and configure software",
  "recipe book containing ingredients and cooking instructions",
  "newsletter update about company achievements",
  "sports match summary with player scores and highlights"
]
samples = sensitive + non
labels = [1]*len(sensitive) + [0]*len(non)
train_context_model(samples, labels)
print("Trained and saved model.")
