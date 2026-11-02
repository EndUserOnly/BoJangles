"""Pending native qualification: bounded file uploads require CORS approval."""
import os,time,json,threading,tempfile,unittest,sys,hashlib
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
RUNTIME=os.environ.get('BOJANGLES_BROKER_RUNTIME')
from bojangles.frontend.framebuffer import SharedFramebuffer
from bojangles.renderer.api import NavigationRequest,RendererStartContext,Viewport
from bojangles.renderer.browser_transport import BrowserCompatibleTransport
from bojangles.renderer.wpe import WPEBackend
from bojangles.renderer.network import RendererRequestBroker
from bojangles.internal.pages import DEFAULT_PAGES
from bojangles.filter.engine import ContentFilter
from bojangles.security.context import DocumentRegistry
from bojangles.security.navigation import NavigationBroker,NavigationSource

class Site(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def reply(self,body=b'ok',mime='text/plain'):
  self.send_response(200);self.send_header('Content-Type',mime);self.send_header('Content-Length',str(len(body)));self.send_header('Access-Control-Allow-Origin',self.server.origin if self.server.approve else 'https://wrong.invalid');self.send_header('Access-Control-Allow-Methods','POST, GET');self.send_header('Access-Control-Allow-Headers','content-type, x-requested-with, x-mime-type');self.end_headers();self.wfile.write(body)
 def do_OPTIONS(self):
  self.server.preflights+=1;self.server.preflight_credentials.append((self.headers.get('Cookie'),self.headers.get('Authorization')));self.reply(b'')
 def do_GET(self):
  if self.path.startswith('/report?'):
   self.server.report=self.path.split('?',1)[1];self.reply();return
  js='''async function send(file){await file.arrayBuffer();await fetch('/endpoint',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Requested-With':'XMLHttpRequest'},body:'hash=fixture&size='+file.size});let x=new XMLHttpRequest();x.open('POST',DEST);x.setRequestHeader('Content-Type','application/octet-stream');x.setRequestHeader('X-Requested-With','XMLHttpRequest');x.setRequestHeader('X-Mime-Type',file.type);x.upload.onprogress=()=>{};x.onload=()=>fetch('/report?success');x.onerror=()=>fetch('/report?error');x.send(file)}'''.replace('DEST',json.dumps(self.server.target))
  if getattr(self.server,'large_file',False):js=js.replace('await file.arrayBuffer()','await file.slice(0,65536).arrayBuffer()')
  self.reply(('<!doctype html><input type=file style="position:absolute;left:10px;top:10px;width:300px;height:60px" onchange="send(this.files[0])"><script>'+js+'</script>').encode(),'text/html')
 def do_POST(self):
  size=int(self.headers.get('Content-Length','0'));total=0;digest=hashlib.sha256()
  while total<size:
   chunk=self.rfile.read(min(65536,size-total))
   if not chunk:break
   total+=len(chunk);digest.update(chunk)
  self.server.posts.append({'path':self.path,'bytes':total,'sha256':digest.hexdigest()});self.reply()

@unittest.skipUnless(RUNTIME,"requires owner-approved rebuilt native runtime")
class CorsBulkUploadRuntime(unittest.TestCase):
 def test_selected_file_handoff_and_denied_origin(self):
  results=[]
  for cross,approve,length in [(False,True,8*1024*1024),(True,True,8*1024*1024),(True,False,8*1024*1024),(True,True,(1<<30)+123)]:
   a=ThreadingHTTPServer(('127.0.0.1',0),Site);b=ThreadingHTTPServer(('127.0.0.1',0),Site);workers=[]
   origin=f'http://127.0.0.1:{a.server_port}';a.large_file=length>(1<<30);a.target=f'http://127.0.0.1:{b.server_port if cross else a.server_port}/receive'
   for server in [a,b]:
    server.origin=origin;server.posts=[];server.report=None;server.preflights=0;server.preflight_credentials=[];server.approve=approve if server is b else True;thread=threading.Thread(target=server.serve_forever);thread.start();workers.append(thread)
   try:
    with tempfile.TemporaryDirectory() as td,SharedFramebuffer.create(640,480) as plane:
     file=Path(td)/'fixture.mp4'
     with file.open('wb') as stream:
      stream.write(b'A'*min(length,8*1024*1024));stream.truncate(length)
     expected=hashlib.sha256()
     with file.open('rb') as stream:
      while chunk:=stream.read(65536):expected.update(chunk)
     expected=expected.hexdigest();runtime=Path(RUNTIME)
     docs=DocumentRegistry(DEFAULT_PAGES);doc=NavigationBroker(docs).navigate(origin+'/',source=NavigationSource.OPERATOR)
     backend=WPEBackend(runtime/'bin/bojangles-wpe',prefix=runtime,extension_dir=runtime/'extensions',transport=BrowserCompatibleTransport(),profile_data_dir=Path(td)/'data',profile_cache_dir=Path(td)/'cache')
     try:
      backend.start(RendererStartContext(plane.target(),Viewport(640,480),doc,RendererRequestBroker(docs,ContentFilter())));backend.load(NavigationRequest(doc.document_id,origin+'/'));clicked=chosen=False;end=time.monotonic()+120
      while a.report is None and time.monotonic()<end:
       events=backend.poll_events()
       if not clicked and any(e.kind.value=='NAVIGATION_FINISHED' for e in events):
        backend.input({'kind':'pointer','x':60,'y':30});backend.input({'kind':'button','button':1,'pressed':True});backend.input({'kind':'button','button':1,'pressed':False});clicked=True
       chooser=next((e for e in events if e.kind.value=='FILE_CHOOSER_REQUESTED'),None)
       if chooser and not chosen:backend.respond_file_chooser(int(chooser.body),(str(file),));chosen=True
       time.sleep(.02)
      result={'expected_length':length,'expected_sha256':expected,'cross_origin':cross,'page_result':a.report,'control_posts':a.posts,'upload_posts':(b.posts if cross else a.posts),'preflights':b.preflights,'preflight_credentials':b.preflight_credentials};results.append(result);print(json.dumps(result),flush=True)
     finally:backend.stop()
   finally:
    for server in [a,b]:server.shutdown();server.server_close()
    for thread in workers:thread.join()
  self.assertEqual(results[0]['page_result'],'success')
  self.assertTrue(any(x['path']=='/receive' for x in results[0]['upload_posts']))
  self.assertEqual(results[1]['page_result'],'success')
  received=next(x for x in results[1]['upload_posts'] if x['path']=='/receive')
  self.assertEqual(received['bytes'],8*1024*1024)
  self.assertEqual(received['sha256'],hashlib.sha256(b'A'*(8*1024*1024)).hexdigest())
  self.assertGreaterEqual(results[1]['preflights'],1)
  self.assertEqual(results[2]['page_result'],'error')
  self.assertEqual(results[2]['upload_posts'],[])
  self.assertGreaterEqual(results[2]['preflights'],1)
  self.assertEqual(results[3]['page_result'],'success')
  large=next(x for x in results[3]['upload_posts'] if x['path']=='/receive')
  self.assertEqual(large['bytes'],results[3]['expected_length'])
  self.assertGreater(large['bytes'],1<<30)
  self.assertEqual(large['sha256'],results[3]['expected_sha256'])
  for result in results:
   self.assertTrue(all(cookie is None and auth is None for cookie,auth in result['preflight_credentials']))
