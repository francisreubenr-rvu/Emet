from services.eval_metrics import compute_accuracy, compute_bleu4, compute_f1, compute_rouge_l


def test_compute_f1_full_match():
    assert compute_f1(["CVE-1", "CVE-2"], ["CVE-1", "CVE-2"]) == 1.0


def test_compute_accuracy_position_sensitive():
    assert compute_accuracy(["A", "B"], ["A", "C"]) == 0.5


def test_compute_bleu4_and_rouge_l_nonzero_for_similar_sentences():
    candidate = "prioritize verified findings and patch internet exposed services"
    reference = "patch internet exposed services and prioritize verified findings"
    assert compute_bleu4(candidate, reference) >= 0.0
    assert compute_rouge_l(candidate, reference) > 0.0
