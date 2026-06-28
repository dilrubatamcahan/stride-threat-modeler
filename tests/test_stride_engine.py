"""
STRIDE Engine birim testleri
Calistirma: python -X utf8 -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from stride_engine import (
    analyze_component,
    analyze_model,
    risk_score,
    risk_level,
    COMPONENT_LABELS,
    COMPONENT_STRIDE_MAP,
    STRIDE_LABELS,
)


class TestRiskScoring:
    def test_max_score(self):
        assert risk_score(5, 5) == 25

    def test_min_score(self):
        assert risk_score(1, 1) == 1

    def test_risk_level_kritik(self):
        label, _ = risk_level(21)
        assert label == "Kritik"

    def test_risk_level_yuksek(self):
        label, _ = risk_level(16)
        assert label == "Yüksek"

    def test_risk_level_orta(self):
        label, _ = risk_level(11)
        assert label == "Orta"

    def test_risk_level_dusuk(self):
        label, _ = risk_level(6)
        assert label == "Düşük"

    def test_risk_level_cok_dusuk(self):
        label, _ = risk_level(3)
        assert label == "Çok Düşük"

    def test_risk_color_not_empty(self):
        _, color = risk_level(20)
        assert color.startswith("#")


class TestComponentAnalysis:
    def test_web_portal_returns_6_threats(self):
        threats = analyze_component("web_portal")
        assert len(threats) == 6

    def test_database_returns_3_threats(self):
        threats = analyze_component("database")
        assert len(threats) == 3

    def test_threats_sorted_by_score_desc(self):
        threats = analyze_component("core_banking")
        scores = [t["risk_skoru"] for t in threats]
        assert scores == sorted(scores, reverse=True)

    def test_threat_has_required_fields(self):
        threats = analyze_component("api_gateway")
        for t in threats:
            assert "baslik" in t
            assert "aciklama" in t
            assert "oneri" in t
            assert "risk_skoru" in t
            assert "risk_seviyesi" in t
            assert "stride_kodu" in t

    def test_unknown_component_returns_empty(self):
        threats = analyze_component("bilinmeyen_bilesen")
        assert threats == []

    def test_all_components_return_threats(self):
        for tip in COMPONENT_STRIDE_MAP:
            threats = analyze_component(tip)
            assert len(threats) > 0, f"{tip} için tehdit döndürülmedi"

    def test_risk_score_positive(self):
        threats = analyze_component("firewall")
        for t in threats:
            assert t["risk_skoru"] > 0

    def test_stride_code_valid(self):
        threats = analyze_component("auth_server")
        valid = set(STRIDE_LABELS.keys())
        for t in threats:
            assert t["stride_kodu"] in valid


class TestModelAnalysis:
    def setup_method(self):
        self.components = [
            {"id": "c1", "tip": "web_portal"},
            {"id": "c2", "tip": "core_banking"},
            {"id": "c3", "tip": "database"},
        ]

    def test_model_returns_correct_component_count(self):
        result = analyze_model(self.components)
        assert len(result["bilesenler"]) == 3

    def test_total_threat_count(self):
        result = analyze_model(self.components)
        expected = 6 + 6 + 3  # web_portal + core_banking + database
        assert result["toplam_tehdit"] == expected

    def test_severity_distribution_keys(self):
        result = analyze_model(self.components)
        for key in ["Kritik", "Yüksek", "Orta", "Düşük", "Çok Düşük"]:
            assert key in result["onem_dagılımı"]

    def test_severity_counts_sum_to_total(self):
        result = analyze_model(self.components)
        total = sum(result["onem_dagılımı"].values())
        assert total == result["toplam_tehdit"]

    def test_components_sorted_by_highest_risk(self):
        result = analyze_model(self.components)
        scores = [b["en_yuksek_risk"] for b in result["bilesenler"]]
        assert scores == sorted(scores, reverse=True)

    def test_empty_model(self):
        result = analyze_model([])
        assert result["toplam_tehdit"] == 0
        assert result["bilesenler"] == []

    def test_all_10_components(self):
        all_comps = [{"id": f"c{i}", "tip": tip} for i, tip in enumerate(COMPONENT_STRIDE_MAP)]
        result = analyze_model(all_comps)
        assert result["toplam_tehdit"] > 0
        assert len(result["bilesenler"]) == 10

    def test_genel_risk_field_exists(self):
        result = analyze_model(self.components)
        assert result["genel_risk"] in ["Kritik", "Yüksek", "Orta", "Düşük"]

    def test_component_label_in_result(self):
        result = analyze_model(self.components)
        for b in result["bilesenler"]:
            assert b["tip_label"] == COMPONENT_LABELS[b["tip"]]


class TestDataIntegrity:
    def test_all_stride_labels_defined(self):
        for cat in ["S", "T", "R", "I", "D", "E"]:
            assert cat in STRIDE_LABELS

    def test_all_component_labels_defined(self):
        for tip in COMPONENT_STRIDE_MAP:
            assert tip in COMPONENT_LABELS

    def test_threat_template_coverage(self):
        from stride_engine import THREAT_TEMPLATES
        for tip, cats in COMPONENT_STRIDE_MAP.items():
            for cat in cats:
                key = (tip, cat)
                assert key in THREAT_TEMPLATES, f"Eksik şablon: {tip} + {cat}"
