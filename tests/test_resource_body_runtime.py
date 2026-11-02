"""Pending native qualification: run only after an owner-approved broker build."""
import os,unittest
from unittest.mock import patch
from bojangles.renderer.wpe_transport import WPEAllowedDataTransport, MAX_RESOURCE_BYTES
from http.server import BaseHTTPRequestHandler
import test_window_print_runtime as fixture

class ApplicationPage(BaseHTTPRequestHandler):
 initialized=False
 def do_GET(self):
  if self.path=='/ready':
   ApplicationPage.initialized=True;body=b'ok';mime='text/plain'
  elif self.path=='/app.js':
   body=b'/*'+b'x'*(10*1024*1024)+b'*/document.title="Application initialized";fetch("/ready");';mime='application/javascript'
  else:body=b'<!doctype html><title>Loading shell</title><script src="/app.js"></script>';mime='text/html'
  self.send_response(200);self.send_header('Content-Type',mime);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass

@unittest.skipUnless(os.environ.get('DISPLAY') and os.environ.get('BOJANGLES_BROKER_RUNTIME'),'requires owner-approved rebuilt native runtime')
class ResourceBodyRuntime(unittest.TestCase):
 open_fixture=fixture.WindowPrintRuntimeTests.open_fixture
 wait_for=fixture.WindowPrintRuntimeTests.wait_for
 close_print_fixture=fixture.WindowPrintRuntimeTests.close_print_fixture
 def test_large_shared_application_script_executes_past_loading_shell(self):
  ApplicationPage.initialized=False
  with patch.object(fixture,'WPEAllowedDataTransport',lambda:WPEAllowedDataTransport(max_resource_bytes=MAX_RESOURCE_BYTES)):
   s,_=self.open_fixture(ApplicationPage,'/start')
  self.wait_for(s,lambda:ApplicationPage.initialized)
  self.assertEqual(s.page_title,'Application initialized')
