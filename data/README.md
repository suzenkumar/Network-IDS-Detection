# data/

Optional folder for **real network-flow datasets**. Nothing here is required —
the project trains on a bundled synthetic corpus so it works offline.

Drop a labelled CSV here and retrain:

```bash
python train_model.py --csv data/nsl-kdd.csv
```

Suggested public sources:

| Dataset | Where | Notes |
|---|---|---|
| NSL-KDD | UNB CSE / Kaggle "NSL-KDD" | best fit — headers match the canonical schema |
| KDD Cup '99 | UCI KDD Archive | same columns as NSL-KDD |
| CICIDS2017 | Canadian Institute for Cybersecurity | different headers; several map via the alias table, the rest are ignored |

CSV files in this folder are git-ignored (they are large).
