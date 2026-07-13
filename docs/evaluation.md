# Evaluation Notes

TARS is easiest to evaluate by looking at whether the architecture records and
uses state responsibly.

## Metrics

- workspace frame count and duplicate winner rate
- high-salience capture rate
- suppressed runtime-noise rate
- typed memory distribution
- contradiction count
- semantic-belief growth
- world prediction resolution rate
- sleep consolidation score
- maturity score from `tars_mind_metrics.py`

## Safe Commands

```bash
python scripts/smoke_memory_hygiene.py
python scripts/smoke_self_model_hygiene.py
python scripts/mind_report.py --json
```

`mind_report.py` reads local JSON/SQLite state. Public demos should use
sanitized sample records rather than private assistant history.
