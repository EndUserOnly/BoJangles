from types import SimpleNamespace
from unittest.mock import Mock
import unittest
from bojangles.frontend.window_session import WindowSession
from bojangles.renderer.api import RendererEvent, RendererEventKind

class MediaIntentTests(unittest.TestCase):
    def session(self, event):
        return SimpleNamespace(manager=SimpleNamespace(poll_events=lambda:[event]), current_document_id='current', media_button=Mock(), status=Mock(), control_panel=Mock(), _update_blocking=Mock(), _offer_drm_retry=Mock(), _offer_selected_live_stream=Mock(), _play_media_candidate=Mock(), _offer_requested_media=Mock())

    def test_discovery_does_not_open_player_even_after_page_click(self):
        for kind in ('file','hls','dash'):
            with self.subTest(kind=kind):
                event=RendererEvent(RendererEventKind.MEDIA_CANDIDATE,'current',uri='https://media.example/video',detail=kind)
                session=self.session(event)
                session._pending_stream_selection=('current',float('inf'),'https://media.example/',False)
                WindowSession._drain_events(session)
                session.media_button.configure.assert_called_once_with(state='normal')
                session._offer_selected_live_stream.assert_not_called()
                session._play_media_candidate.assert_not_called()

    def test_explicit_play_still_reaches_existing_authorization(self):
        event=RendererEvent(RendererEventKind.MEDIA_REQUESTED,'current',uri='https://media.example/video')
        session=self.session(event)
        WindowSession._drain_events(session)
        session._offer_requested_media.assert_called_once_with(event)

    def test_retired_document_discovery_is_ignored(self):
        event=RendererEvent(RendererEventKind.MEDIA_CANDIDATE,'retired',uri='https://media.example/video')
        session=self.session(event)
        WindowSession._drain_events(session)
        session.media_button.configure.assert_not_called()
