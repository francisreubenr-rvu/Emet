from __future__ import annotations

from collections import Counter


def _ngrams(tokens: list[str], n: int) -> list[tuple[str, ...]]:
    if len(tokens) < n:
        return []
    return [tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1)]


def compute_accuracy(predicted: list[str], expected: list[str]) -> float:
    if not expected:
        return 1.0
    hit = sum(1 for idx, value in enumerate(expected) if idx < len(predicted) and predicted[idx] == value)
    return round(hit / len(expected), 4)


def compute_f1(predicted: list[str], expected: list[str]) -> float:
    p = set(predicted)
    e = set(expected)
    if not p and not e:
        return 1.0
    if not p or not e:
        return 0.0
    tp = len(p & e)
    precision = tp / len(p)
    recall = tp / len(e)
    if precision + recall == 0:
        return 0.0
    return round((2 * precision * recall) / (precision + recall), 4)


def compute_bleu4(candidate: str, reference: str) -> float:
    c_tokens = candidate.lower().split()
    r_tokens = reference.lower().split()
    if not c_tokens or not r_tokens:
        return 0.0

    precisions: list[float] = []
    for n in range(1, 5):
        c_ngrams = Counter(_ngrams(c_tokens, n))
        r_ngrams = Counter(_ngrams(r_tokens, n))
        if not c_ngrams:
            precisions.append(0.0)
            continue
        overlap = sum(min(count, r_ngrams[gram]) for gram, count in c_ngrams.items())
        precisions.append(overlap / sum(c_ngrams.values()))

    non_zero = [value for value in precisions if value > 0]
    if len(non_zero) < 4:
        return 0.0

    from math import exp, log

    geo_mean = exp(sum(log(value) for value in precisions) / 4)
    brevity_penalty = min(1.0, exp(1 - (len(r_tokens) / max(1, len(c_tokens)))))
    return round(geo_mean * brevity_penalty, 4)


def compute_rouge_l(candidate: str, reference: str) -> float:
    c = candidate.lower().split()
    r = reference.lower().split()
    if not c or not r:
        return 0.0

    dp = [[0] * (len(r) + 1) for _ in range(len(c) + 1)]
    for i in range(1, len(c) + 1):
        for j in range(1, len(r) + 1):
            if c[i - 1] == r[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

    lcs = dp[len(c)][len(r)]
    precision = lcs / len(c)
    recall = lcs / len(r)
    if precision + recall == 0:
        return 0.0
    beta = 1.2
    score = ((1 + beta**2) * precision * recall) / (recall + beta**2 * precision)
    return round(score, 4)


def evaluate_fixture(*, predicted_cves: list[str], expected_cves: list[str], candidate_answer: str, reference_answer: str) -> dict:
    return {
        "f1": compute_f1(predicted_cves, expected_cves),
        "bleu4": compute_bleu4(candidate_answer, reference_answer),
        "rougeL": compute_rouge_l(candidate_answer, reference_answer),
        "accuracy": compute_accuracy(predicted_cves, expected_cves),
    }
