"""Opt-in anonymous live-site qualification; no login or persistent worker."""
import os, time, unittest, email, re
from pathlib import Path
from bojangles.frontend.window_session import WindowSession, abgr_to_rgb
from bojangles.renderer.wpe import WPEBackend
from bojangles.renderer.browser_transport import BrowserCompatibleTransport
from bojangles.renderer.wpe_transport import MAX_RESOURCE_BYTES
from PIL import Image

@unittest.skipUnless(os.environ.get('BOJANGLES_LIVE_CHECKS'), 'explicit live checks required')
class HeaderLiveSites(unittest.TestCase):
    def test_live_sites(self):
        prefix = Path(os.environ['BOJANGLES_BROKER_RUNTIME'])
        for label, url in [('youtube','https://www.youtube.com/@DauerwelleDemoReport/streams'),
                           ('1984','https://1984.hosting/'),
                           ('wordpress','https://wordpress.org/')]:
            with self.subTest(site=label):
                sizes = []
                def factory():
                    t = BrowserCompatibleTransport(max_resource_bytes=MAX_RESOURCE_BYTES)
                    clean = t.sanitize_response_headers
                    def measure(pairs):
                        cleaned = clean(pairs)
                        sizes.append(sum(len(k.encode())+len(v.encode())+4 for k,v in cleaned))
                        return cleaned
                    t.sanitize_response_headers = measure
                    return WPEBackend(prefix/'bin/bojangles-wpe',prefix=prefix,extension_dir=prefix/'extensions',transport=t,
                        profile_data_dir=Path(os.environ['HOME'])/label/'data',profile_cache_dir=Path(os.environ['HOME'])/label/'cache')
                s = WindowSession(url, renderer_factories={'wpe':factory})
                try:
                    # Hold the qualification viewport fixed, as in native fixtures.
                    s.image_label.unbind('<Configure>')
                    s._initial_navigation()
                    s._refresh_frame()
                    s._pump_events()
                    end = time.monotonic()+75
                    initialized = False
                    while time.monotonic()<end:
                        s.root.update()
                        if s.page_title and sizes and len(set(s.plane.bytes())) > 4 and 'failed' not in s.status.get().lower():
                            if label == 'youtube':
                                archive = email.message_from_bytes(s.manager.backend.export_page('mhtml'))
                                documents = [part.get_payload(decode=True).decode('utf-8', errors='replace')
                                             for part in archive.walk() if part.get_content_type() == 'text/html']
                                initialized = any(re.search(
                                    r'<ytd-(?:rich-item|grid-video|video)-renderer\b[^>]*>.*?<a\b[^>]*href=[\"\'](?:https://www\.youtube\.com)?/watch\?v=[^\"\']+[^>]*>.*?</a>',
                                    html, re.S) for html in documents)
                                if not initialized:
                                    time.sleep(2)
                                    continue
                            else:
                                initialized = True
                            time.sleep(2)
                            s.root.update()
                            break
                        if s.status.get().startswith('Navigation failed'): break
                        time.sleep(.05)
                    if label == 'youtube':
                        (Path(os.environ['BOJANGLES_LIVE_OUTPUT'])/'youtube.mhtml').write_bytes(s.manager.backend.export_page('mhtml'))
                    print('LIVE',label,'title=',s.page_title,'status=',s.status.get(),'largest_headers=',max(sizes,default=0),flush=True)
                    self.assertTrue(initialized, "Page remained a loading shell without rendered stream entries")
                    self.assertTrue(s.page_title)
                    self.assertNotIn('Navigation failed',s.status.get())
                    pixels=abgr_to_rgb(s.plane.bytes())
                    self.assertGreater(len(set(pixels)), 4)
                    Image.frombytes('RGB',(s.WIDTH,s.HEIGHT),pixels).save(Path(os.environ['BOJANGLES_LIVE_OUTPUT'])/(label+'.png'))
                finally:
                    from test_window_history_runtime import close_fixture_session
                    close_fixture_session(s)
