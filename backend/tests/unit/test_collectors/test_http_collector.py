from app.collectors.http_collector import _detect_clickfix_fake_verification


def test_detect_clickfix_fake_verification_terminal_paste_flow():
    body = """
    <h1>Verify you are human by completing the action below.</h1>
    <p>Additional Verification Required</p>
    <ol>
      <li>Press Win + R</li>
      <li>Type Terminal in the menu</li>
      <li>Press Ctrl + V to paste the command</li>
      <li>Press Enter to continue</li>
    </ol>
    """

    assert _detect_clickfix_fake_verification(body) is True


def test_detect_clickfix_fake_verification_does_not_flag_plain_captcha():
    body = """
    <h1>Verify you are human</h1>
    <p>Please complete the CAPTCHA challenge in your browser.</p>
    """

    assert _detect_clickfix_fake_verification(body) is False
