"""
Deep tests for ConfidencePool and TreeConfidence.

Covers:
- Initial score is 0.0
- add_boost: diminishing-returns formula
- add_boost: negative penalty
- add_boost: idempotency (same source fires only once)
- add_boost: clamped to [0.0, 1.0]
- add_boost: boost cap at ±1.0
- ConfidencePool.apply_boost: delegates correctly
- ConfidencePool.freeze: blocks further boosts
- ConfidencePool.get_scores: aggregates all tree scores
- ConfidencePool.clear: full reset
- get_tree_confidence: auto-creates on first access
- Multiple trees are isolated
"""
import pytest

from lattice_mind.core.confidence import BoostRecord, ConfidencePool, TreeConfidence

# ──────────────────────────────────────────────────────────────────────────────
# TreeConfidence
# ──────────────────────────────────────────────────────────────────────────────

class TestTreeConfidence:

    def mk(self, tree_id="tree_a"):
        return TreeConfidence(tree_id=tree_id)

    def test_initial_score_zero(self):
        tc = self.mk()
        assert tc.score == 0.0

    def test_initial_sources_empty(self):
        tc = self.mk()
        assert tc.sources == []

    # ── Diminishing-returns formula ───────────────────────────────────────────

    def test_single_boost_formula(self):
        tc = self.mk()
        applied = tc.add_boost(0.5, "source_a")
        # new_score = 0 + 0.5 * (1 - 0) = 0.5
        assert abs(tc.score - 0.5) < 1e-9
        assert abs(applied - 0.5) < 1e-9

    def test_two_positive_boosts_diminishing(self):
        tc = self.mk()
        tc.add_boost(0.5, "a")  # score = 0.5
        tc.add_boost(0.5, "b")  # applied = 0.5 * (1 - 0.5) = 0.25; score = 0.75
        assert abs(tc.score - 0.75) < 1e-9

    def test_score_never_exceeds_1(self):
        tc = self.mk()
        for i in range(200):
            tc.add_boost(0.5, f"src_{i}")
        assert tc.score <= 1.0

    def test_score_never_drops_below_0_on_penalty_from_zero(self):
        tc = self.mk()
        tc.add_boost(-0.5, "penalty")
        assert tc.score >= 0.0

    # ── Negative (penalty) boosts ─────────────────────────────────────────────

    def test_penalty_from_positive_score(self):
        tc = self.mk()
        tc.add_boost(0.8, "first")           # score ≈ 0.8
        applied = tc.add_boost(-0.5, "pen")  # applied = 0.8 * -0.5 = -0.4
        assert tc.score == pytest.approx(0.8 + (-0.4), abs=1e-9)
        assert applied < 0

    def test_penalty_reduces_score(self):
        tc = self.mk()
        tc.add_boost(1.0, "up")      # score ≈ 1.0
        tc.add_boost(-0.3, "down")   # should reduce
        assert tc.score < 1.0

    # ── Idempotency (same source_id only fires once) ──────────────────────────

    def test_same_source_fires_once(self):
        tc = self.mk()
        tc.add_boost(0.5, "src", phase="detection")
        tc.add_boost(0.5, "src", phase="detection")  # same source_id → ignored
        assert abs(tc.score - 0.5) < 1e-9

    def test_different_phase_same_label_fires(self):
        tc = self.mk()
        tc.add_boost(0.5, "src", phase="seed")
        tc.add_boost(0.5, "src", phase="detection")  # different phase → fires
        assert tc.score > 0.5

    def test_returns_zero_for_duplicate(self):
        tc = self.mk()
        tc.add_boost(0.5, "src")
        returned = tc.add_boost(0.5, "src")
        assert returned == 0.0

    # ── Boost clamping ────────────────────────────────────────────────────────

    def test_boost_capped_at_1(self):
        tc = self.mk()
        tc.add_boost(999.0, "big")  # should be capped at 1.0
        assert tc.score <= 1.0

    def test_boost_capped_at_minus_1(self):
        tc = self.mk()
        tc.add_boost(0.8, "up")
        tc.add_boost(-999.0, "big_penalty")
        assert tc.score >= 0.0

    # ── BoostRecord creation ──────────────────────────────────────────────────

    def test_boost_record_added(self):
        tc = self.mk()
        tc.add_boost(0.3, "mysrc")
        assert len(tc.sources) == 1
        rec = tc.sources[0]
        assert isinstance(rec, BoostRecord)
        assert rec.boost == 0.3
        assert abs(rec.applied - 0.3) < 1e-9

    def test_duplicate_record_not_added(self):
        tc = self.mk()
        tc.add_boost(0.3, "src")
        tc.add_boost(0.3, "src")
        assert len(tc.sources) == 1  # second one ignored


# ──────────────────────────────────────────────────────────────────────────────
# ConfidencePool
# ──────────────────────────────────────────────────────────────────────────────

class TestConfidencePool:

    def mk(self):
        return ConfidencePool()

    def test_initially_not_frozen(self):
        pool = self.mk()
        assert pool.frozen is False

    def test_get_tree_confidence_creates_new(self):
        pool = self.mk()
        tc = pool.get_tree_confidence("tree_x")
        assert isinstance(tc, TreeConfidence)
        assert tc.tree_id == "tree_x"

    def test_get_tree_confidence_same_instance(self):
        pool = self.mk()
        t1 = pool.get_tree_confidence("tree_x")
        t2 = pool.get_tree_confidence("tree_x")
        assert t1 is t2

    def test_apply_boost_delegates_to_tree(self):
        pool = self.mk()
        pool.apply_boost("tree_x", 0.5, "source")
        score = pool.get_tree_confidence("tree_x").score
        assert abs(score - 0.5) < 1e-9

    def test_apply_boost_returns_applied(self):
        pool = self.mk()
        applied = pool.apply_boost("tree_x", 0.4, "src")
        assert abs(applied - 0.4) < 1e-9

    def test_freeze_blocks_boosts(self):
        pool = self.mk()
        pool.apply_boost("tree_x", 0.5, "before")
        pool.freeze()
        pool.apply_boost("tree_x", 0.5, "after")
        # Score should still be 0.5, not increase to 0.75
        score = pool.get_tree_confidence("tree_x").score
        assert abs(score - 0.5) < 1e-9

    def test_freeze_returns_zero(self):
        pool = self.mk()
        pool.freeze()
        returned = pool.apply_boost("tree_x", 0.5, "blocked")
        assert returned == 0.0

    def test_get_scores_aggregates(self):
        pool = self.mk()
        pool.apply_boost("tree_a", 0.5, "a")
        pool.apply_boost("tree_b", 0.3, "b")
        scores = pool.get_scores()
        assert "tree_a" in scores
        assert "tree_b" in scores
        assert abs(scores["tree_a"] - 0.5) < 1e-9
        assert abs(scores["tree_b"] - 0.3) < 1e-9

    def test_get_scores_empty(self):
        pool = self.mk()
        assert pool.get_scores() == {}

    def test_clear_resets_trees(self):
        pool = self.mk()
        pool.apply_boost("tree_x", 0.8, "src")
        pool.clear()
        assert pool.get_scores() == {}

    def test_clear_unfreezes(self):
        pool = self.mk()
        pool.freeze()
        pool.clear()
        assert pool.frozen is False

    def test_clear_allows_new_boost(self):
        pool = self.mk()
        pool.apply_boost("tree_x", 0.5, "a")
        pool.clear()
        pool.apply_boost("tree_x", 0.3, "b")
        assert abs(pool.get_tree_confidence("tree_x").score - 0.3) < 1e-9

    def test_isolation_between_trees(self):
        pool = self.mk()
        pool.apply_boost("tree_a", 0.9, "src")
        pool.apply_boost("tree_b", 0.1, "src")
        a_score = pool.get_tree_confidence("tree_a").score
        b_score = pool.get_tree_confidence("tree_b").score
        assert abs(a_score - 0.9) < 1e-9
        assert abs(b_score - 0.1) < 1e-9

    def test_multiple_boosts_to_same_tree(self):
        pool = self.mk()
        pool.apply_boost("tree_x", 0.5, "a")  # score = 0.5
        pool.apply_boost("tree_x", 0.5, "b")  # applied = 0.25; score = 0.75
        assert abs(pool.get_tree_confidence("tree_x").score - 0.75) < 1e-9

    def test_freeze_flag_is_true(self):
        pool = self.mk()
        pool.freeze()
        assert pool.frozen is True

    def test_unfreeze_allows_boosts_after_freeze(self):
        pool = self.mk()
        pool.freeze()
        assert pool.apply_boost("tree_x", 0.5, "blocked") == 0.0
        pool.unfreeze()
        applied = pool.apply_boost("tree_x", 0.4, "after")
        assert applied > 0.0
        assert abs(pool.get_tree_confidence("tree_x").score - 0.4) < 1e-9
