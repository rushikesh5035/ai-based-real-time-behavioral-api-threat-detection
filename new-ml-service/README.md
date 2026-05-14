# New ML Service (Parallel Track)

Independent and safe experiment track for your final-year project without changing old `ml-service`.

## 3-Stage Training Funnel

1. Stage A: Resampling filter
- Methods: `none`, `oversampling`, `undersampling`, `smote`, `smoteenn` (ROSE practical substitute)
- Model: RandomForest baseline
- Output: top-2 resampling methods by macro-F1

2. Stage B: Scaling filter
- For top-2 resampling methods, test scaling: `none`, `minmax`, `standard`
- Model: RandomForest baseline
- Output: best resampling + scaling combo

3. Stage C: Final model comparison
- Models: RandomForest, XGBoost, SVM, LogisticRegression, NaiveBayes
- Uses best combo from Stage B
- Best model selected by macro-F1

## Quick Run

```bash
cd new-ml-service
pip install -r requirements.txt
python scripts/generate_behavioral_dataset.py --rows 6000 --seed 42
python scripts/train_pipeline.py
python scripts/evaluate_pipeline.py
python app.py
```

## Artifacts

- Dataset: `data/raw/behavioral_api_dataset_v2.csv`
- Split: `data/processed/X_train.csv`, `X_test.csv`, `y_train.csv`, `y_test.csv`
- Stored resampled datasets: `data/imbalanced/X_<technique>.csv`, `y_<technique>.csv`
- Reports:
  - `reports/stage_a_resampling_results.csv`
  - `reports/stage_b_scaling_results.csv`
  - `reports/stage_c_model_comparison.csv`
  - `reports/final_selection_summary.csv`
  - `reports/model_results_v2.csv`
  - `reports/classification_report_v2.txt`
- Final model: `model/api_security_pipeline_v2.pkl`