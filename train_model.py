import sys

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report


def normalize_label(value):
    text = str(value).strip().lower()
    if text in ['1', 'phishing', 'phish', 'malicious', 'spam']:
        return 1
    if text in ['0', 'safe', 'legitimate', 'ham', 'benign']:
        return 0
    raise ValueError(f'Unsupported label: {value}')


def main():
    if len(sys.argv) != 2:
        print('Usage: python train_model.py path/to/dataset.csv')
        return

    dataset_path = sys.argv[1]
    data = pd.read_csv(dataset_path)
    if 'text' not in data.columns or 'label' not in data.columns:
        raise ValueError('Dataset must contain columns: text,label')

    data = data.dropna(subset=['text', 'label']).copy()
    data['label'] = data['label'].apply(normalize_label)

    class_counts = data['label'].value_counts()
    stratify_labels = data['label'] if data['label'].nunique() == 2 and class_counts.min() >= 2 else None

    x_train, x_test, y_train, y_test = train_test_split(
        data['text'],
        data['label'],
        test_size=0.2,
        random_state=42,
        stratify=stratify_labels,
    )

    model = Pipeline([
        ('tfidf', TfidfVectorizer(stop_words='english', max_features=10000, ngram_range=(1, 2))),
        ('classifier', LogisticRegression(max_iter=1000)),
    ])
    model.fit(x_train, y_train)

    predictions = model.predict(x_test)
    print(f'Accuracy: {accuracy_score(y_test, predictions):.3f}')
    print(classification_report(y_test, predictions, labels=[0, 1], target_names=['safe', 'phishing'], zero_division=0))

    joblib.dump(model, 'phishing_model.pkl')
    print('Saved trained model to phishing_model.pkl')


if __name__ == '__main__':
    main()
