"""Cat Shell Risk Commander as a Jev / System One shaped HTTP endpoint.

Serves POST /v1/systemone for the safe-yolo plugin: one state (a shell command),
one choice question (safe / unsafe). The underlying classifier scores the text
and never executes it. Confidence is the distance from the policy threshold
mapped through a sigmoid, so the plugin's cascade escalates borderline
commands to a stronger model.
"""
import math
import sys

from fastapi import FastAPI

sys.path.insert(0, "/model")
from shell_cat_guard_a1 import ShellRiskClassifier  # noqa: E402

classifier = ShellRiskClassifier("/model/model.json")

app = FastAPI(title="catshell", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/health")
def health():
    return {"status": "ok", "service": "catshell"}


@app.post("/v1/systemone")
def systemone(body: dict):
    state = str(body.get("state") or "")
    r = classifier.score(state)
    score = r["decision_score"]
    threshold = r["threshold"]
    # distance from the policy threshold through a sigmoid: large scores are
    # confident verdicts, borderline ones fall below the plugin's threshold
    # and escalate
    confidence = 1 / (1 + math.exp(-abs(score - threshold)))
    choice = "unsafe" if score > threshold else "safe"
    return {
        "answers": {
            "verdict": {
                "type": "choice",
                "choice": choice,
                "confidence": round(confidence, 4),
                "answer_confidence": round(confidence, 4),
            }
        },
        "catshell": {"decision_score": round(score, 4), "threshold": round(threshold, 4)},
    }
