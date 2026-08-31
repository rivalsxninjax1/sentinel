import pytest
from pydantic import ValidationError

from app.llm.schemas import EndpointClassification, ParameterSemantic, RecommendedTest


def test_valid_classification_parses():
    c = EndpointClassification(
        endpoint="/api/users/{id}",
        parameter="id",
        classification="identifier",
        risk_score=9,
        recommended_tests=["bola", "authorization"],
        reason="Authenticated endpoint exposes a user-controlled object identifier",
    )
    assert c.classification == ParameterSemantic.IDENTIFIER
    assert RecommendedTest.BOLA in c.recommended_tests


def test_risk_score_out_of_range_rejected():
    with pytest.raises(ValidationError):
        EndpointClassification(
            endpoint="/x",
            classification="identifier",
            risk_score=11,
            reason="x",
        )


def test_unknown_classification_value_rejected():
    with pytest.raises(ValidationError):
        EndpointClassification(
            endpoint="/x",
            classification="not_a_real_category",
            risk_score=5,
            reason="x",
        )


def test_unknown_recommended_test_rejected():
    with pytest.raises(ValidationError):
        EndpointClassification(
            endpoint="/x",
            classification="identifier",
            risk_score=5,
            recommended_tests=["made_up_test"],
            reason="x",
        )


def test_defaults_when_optional_fields_omitted():
    c = EndpointClassification(endpoint="/x", classification="unknown", risk_score=0, reason="x")
    assert c.parameter is None
    assert c.recommended_tests == []
