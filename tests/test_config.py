from vulnerability_agent.config import Settings


def test_empty_base_url_uses_default_openai_endpoint():
    settings = Settings(openai_api_key="test", openai_base_url="  ")
    assert settings.openai_base_url is None


def test_custom_base_url_is_preserved():
    settings = Settings(openai_api_key="test", openai_base_url="https://gateway.example/v1")
    assert settings.openai_base_url == "https://gateway.example/v1"
