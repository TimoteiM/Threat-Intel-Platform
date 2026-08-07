from app.collectors.js_analysis import classify_rendered_form_controls


def test_detects_visible_vehicle_registration_form_without_values():
    result = classify_rendered_form_controls([
        {
            "form_index": 1,
            "tag": "input",
            "type": "text",
            "label": "Numărul de înmatriculare al vehiculului implicat",
            "placeholder": "Ex. B 12 ABC",
            "name": "registration",
            "visible": True,
            "required": True,
            "has_submit_control": True,
            "bounds": {"x": 10, "y": 20, "width": 300, "height": 40},
            "value": "must-not-be-retained",
        }
    ])

    assert result["detected"] is True
    assert result["confidence"] == "high"
    assert result["categories"] == ["vehicle_identifier"]
    assert result["interaction_required"] is True
    assert result["controls"][0]["label"].startswith("Numărul")
    assert "value" not in result["controls"][0]


def test_ignores_hidden_and_non_data_controls():
    result = classify_rendered_form_controls([
        {"form_index": 1, "tag": "input", "type": "hidden", "visible": True},
        {"form_index": 1, "tag": "input", "type": "text", "visible": False},
        {"form_index": 1, "tag": "input", "type": "checkbox", "visible": True},
    ])

    assert result["detected"] is False
    assert result["visible_control_count"] == 0


def test_classifies_payment_and_credential_fields():
    result = classify_rendered_form_controls([
        {"form_index": 1, "tag": "input", "type": "password", "visible": True},
        {
            "form_index": 1,
            "tag": "input",
            "type": "text",
            "autocomplete": "cc-number",
            "label": "Credit card number",
            "visible": True,
        },
    ])

    assert result["confidence"] == "high"
    assert result["categories"] == ["credential", "payment"]
