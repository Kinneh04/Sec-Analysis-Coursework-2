import numpy as np
import pandas as pd

from src.v3.fit import CalibratedModel, training_weights, PE64_MACHINE


def test_training_weights_upweight_x64_malware():
    df = pd.DataFrame({
        "label": [0, 1, 1],
        "pe1s_machine": [PE64_MACHINE, PE64_MACHINE, 332],
    })
    w = training_weights(df)
    assert w.tolist() == [1.0, 3.0, 1.0]


class _Dummy:
    def predict_proba(self, X):
        p = np.array([0.2, 0.8])[: len(X)]
        return np.column_stack([1 - p, p])


def test_calibrated_model_monotonic():
    from sklearn.isotonic import IsotonicRegression
    iso = IsotonicRegression(out_of_bounds="clip")
    iso.fit(np.array([0.1, 0.5, 0.9]), np.array([0, 0, 1]))
    m = CalibratedModel(_Dummy(), iso)
    p = m.predict_proba(pd.DataFrame({"x": [0, 1]}))[:, 1]
    assert p[1] > p[0]
