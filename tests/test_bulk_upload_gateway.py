"""Trusted gateway integration: denied preflight sends zero file bytes."""
import fcntl,hashlib,os,threading,unittest,tempfile
from pathlib import Path
from bojangles.renderer.upload_body import SelectedFile
from types import SimpleNamespace
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from bojangles.renderer.wpe import WPEBackend
from bojangles.renderer.browser_transport import BrowserCompatibleTransport
from bojangles.renderer.native_protocol import NativeMessage,NativePacket,pack_strings
from bojangles.renderer.api import NavigationRequest
from bojangles.renderer.network import RendererRequestBroker
from bojangles.filter.engine import ContentFilter
from bojangles.internal.pages import DEFAULT_PAGES
from bojangles.security.context import DocumentRegistry
from bojangles.security.navigation import NavigationBroker,NavigationSource

class UploadServer(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_OPTIONS(self):
  self.server.calls.append(('OPTIONS',self.headers.get('Cookie'),self.headers.get('Authorization')))
  self.send_response(200);self.send_header('Access-Control-Allow-Origin',self.server.origin if self.server.approve else 'https://wrong.invalid');self.send_header('Access-Control-Allow-Methods','POST');self.send_header('Access-Control-Allow-Headers','content-type, x-requested-with, x-mime-type');self.send_header('Content-Length','0');self.end_headers()
 def do_POST(self):
  body=self.rfile.read(int(self.headers['Content-Length']));self.server.calls.append(('POST',len(body),hashlib.sha256(body).hexdigest()));self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'ok')

class BulkUploadGateway(unittest.TestCase):
 def test_real_cross_origin_file_transfer_follows_preflight_or_sends_no_body(self):
  for approve,selected in [(True,False),(False,False),(True,True),(False,True)]:
   with self.subTest(approve=approve,selected=selected):
    server=ThreadingHTTPServer(('127.0.0.1',0),UploadServer);server.origin='http://127.0.0.1:1';server.approve=approve;server.calls=[]
    worker=threading.Thread(target=server.serve_forever);worker.start()
    try:
     origin=server.origin+'/';url=f'http://127.0.0.1:{server.server_port}/receive'
     docs=DocumentRegistry(DEFAULT_PAGES);doc=NavigationBroker(docs).navigate(origin,source=NavigationSource.OPERATOR)
     backend=WPEBackend('/unused',prefix='/unused',extension_dir='/unused',transport=BrowserCompatibleTransport())
     backend._context=SimpleNamespace(document=doc,request_channel=RendererRequestBroker(docs,ContentFilter()));backend._request=NavigationRequest(doc.document_id,origin)
     sent=[];backend._send=lambda packet,*args:sent.append(packet)
     body=b'A'*(8*1024*1024);fd=os.memfd_create('synthetic-upload',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
     os.write(fd,body);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_SEAL|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_WRITE)
     headers=[('Origin',server.origin),('Sec-Fetch-Mode','cors'),('Sec-BoJangles-Credentials','omit'),('Content-Type','application/octet-stream'),('X-Requested-With','XMLHttpRequest'),('X-Mime-Type','video/mp4')]
     fields=[doc.document_id,url,'OTHER',origin,'POST','stage5d',str(len(body)),str(len(headers))]
     for pair in headers:fields.extend(pair)
     with tempfile.TemporaryDirectory(prefix='selected-upload-gateway-') as temporary:
      if selected:
       # A denied >1GiB file tests authorization without sending its contents.
       path=Path(temporary)/'selected.bin';path.write_bytes(body)
       length=len(body) if approve else (1<<30)+1
       with path.open('r+b') as stream:stream.truncate(length)
       path.chmod(0o400);key='/state/uploads/nonce/selected.bin'
       backend._selected_upload_files[key]=SelectedFile.capture(path,doc.document_id)
       os.close(fd);fd=os.memfd_create('inline-only',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
       fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_SEAL|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_WRITE)
       fields[5]='stage5f-files-stats';fields[6]=str(length)
       fields.extend(['7','0','1','file',key,'0',str(length)])
      backend._handle_resource_request(NativePacket(NativeMessage.RESOURCE_REQUEST,1,pack_strings(*fields)),fd)
     self.assertEqual(server.calls[0],('OPTIONS',None,None))
     if approve:
      self.assertEqual(server.calls[1],('POST',len(body),hashlib.sha256(body).hexdigest()))
      self.assertEqual(sent[-1].kind,NativeMessage.RESOURCE_DATA)
     else:
      self.assertEqual(len(server.calls),1);self.assertEqual(sent[-1].kind,NativeMessage.RESOURCE_DECISION)
    finally:server.shutdown();server.server_close();worker.join()
