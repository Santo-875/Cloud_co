from unittest.mock import MagicMock, patch

from streamlit.testing.v1 import AppTest


def test_ui_honors_api_base_url(monkeypatch):
    custom_url = "http://custom-api-endpoint:9999"
    monkeypatch.setenv("API_BASE_URL", custom_url)

    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"id": "test_id_123", "name": "custom_arch"}
        mock_client.post.return_value = mock_resp

        # Mock sub-calls triggered once active_id is set
        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = {"nodes": [], "edges": [], "clusters": []}
        mock_client.get.return_value = mock_get_resp

        at = AppTest.from_file("../ui/streamlit_app.py")
        at.run()

        # Check button label was renamed
        parse_btn = next((b for b in at.button if "Parse & Load" in b.label), None)
        assert (
            parse_btn is not None
        ), "Renamed 'Parse & Load Architecture' button should exist"

        # Input YAML and click
        at.text_area[0].input(
            "name: custom_arch\nregion: us-east-1\nresources: []"
        ).run()
        parse_btn.click().run()

        # Verify httpx.Client was called with the custom base_url
        assert any(
            call.kwargs.get("base_url") == custom_url
            for call in mock_client_cls.call_args_list
        ), f"Expected httpx.Client with base_url={custom_url}, got {mock_client_cls.call_args_list}"

        assert not at.exception
