import joblib, pandas as pd, numpy as np
from sklearn.inspection import permutation_importance
from sklearn.metrics import mutual_info_score

pipe = joblib.load('model/api_security_pipeline.pkl')
X = pd.read_csv('data/processed/X_train.csv')
y = pd.read_csv('data/processed/y_train.csv').squeeze()

# Try to get feature names
feat_names = None
try:
    pre = pipe.named_steps.get('preprocessor')
    feat_names = list(pre.get_feature_names_out())
except Exception:
    try:
        feat_names = X.columns.tolist()
    except Exception:
        feat_names = [f'f{i}' for i in range(X.shape[1])]

print('num features:', len(feat_names))

# Feature importances if available
est = None
try:
    est = pipe.named_steps.get('model')
except Exception:
    est = pipe.steps[-1][1]

if hasattr(est, 'feature_importances_'):
    importances = est.feature_importances_
    s = sorted(zip(feat_names, importances), key=lambda x: x[1], reverse=True)[:20]
    print('\nTop feature importances:')
    for f, imp in s:
        print(f, imp)
else:
    print('\nNo tree-based importances; running permutation importance (this may take a few seconds)...')
    r = permutation_importance(pipe, X, y, n_repeats=10, random_state=42, n_jobs=1)
    s = sorted(zip(feat_names, r.importances_mean), key=lambda x: x[1], reverse=True)[:20]
    for f, imp in s:
        print(f, imp)

# Check per-feature if any single value perfectly maps to a single label
perfect_predictors = []
for col in X.columns:
    df = pd.concat([X[col].astype(str), y.astype(str)], axis=1)
    groups = df.groupby(col)[y.name].nunique()
    if (groups <= 1).all():
        perfect_predictors.append(col)

print('\nPerfect predictors (category -> single label for all values):', perfect_predictors)

# Check if any numeric feature exactly maps deterministically to the label
exact_match = []
for col in X.columns:
    try:
        mapping = {}
        ok = True
        for v, lab in zip(X[col].astype(object), y):
            if v in mapping and mapping[v] != lab:
                ok = False; break
            mapping[v]=lab
        if ok and len(mapping)>1:
            exact_match.append(col)
    except Exception:
        pass
print('Potential exact-match features:', exact_match)

# Mutual information
mi = {}
for col in X.columns:
    try:
        mi[col] = mutual_info_score(y, X[col].astype(str))
    except Exception:
        mi[col] = 0.0
sorted_mi = sorted(mi.items(), key=lambda x: x[1], reverse=True)
print('\nTop mutual-info features:')
for k,v in sorted_mi[:10]:
    print(k, v)

# Basic class distribution
print('\nClass distribution in y_train:')
print(y.value_counts())

print('\nDiagnostics complete')
