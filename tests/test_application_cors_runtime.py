"""Application headers and native credential modes across two real origins."""
import json,os,tempfile,threading,time,unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit,parse_qs
from bojangles.renderer.browser_transport import BrowserCompatibleTransport
from bojangles.renderer.wpe_transport import WPEAllowedDataTransport
from bojangles.renderer.wpe import WPEBackend
from bojangles.frontend.framebuffer import SharedFramebuffer
from bojangles.renderer.api import NavigationRequest,RendererStartContext,Viewport
from bojangles.internal.pages import DEFAULT_PAGES
from bojangles.renderer.network import RendererRequestBroker
from bojangles.filter.engine import ContentFilter
from bojangles.security.context import DocumentRegistry
from bojangles.security.navigation import NavigationBroker,NavigationSource
class Site(BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def reply(self,body=b'ok'):
  self.send_response(200);self.send_header('Content-Type','text/html');self.send_header('Content-Length',str(len(body)))
  p=urlsplit(self.path).path
  if p=='/':self.send_header('Set-Cookie','fixture=host-cookie; Path=/; SameSite=Lax')
  else:
   self.send_header('Access-Control-Allow-Origin',self.server.origin if p=='/include' else '*')
   self.send_header('Access-Control-Allow-Credentials','true')
   self.send_header('Access-Control-Allow-Methods','GET, POST')
   self.send_header('Access-Control-Allow-Headers','*' if p in {'/wild','/auth-wild'} else 'content-type, x-application-key, authorization')
  self.end_headers();self.wfile.write(body)
 def do_OPTIONS(self):
  self.server.preflights.append((urlsplit(self.path).path,self.headers.get('Cookie'),self.headers.get('Authorization'),self.headers.get('Access-Control-Request-Headers')));self.reply()
 def do_GET(self):
  p=urlsplit(self.path).path
  if p=='/':
   js='''(async()=>{const b=BASE;let r={};
   r.custom=await fetch(b+'/custom',{headers:{'X-Application-Key':'generic-value'}}).then(x=>x.text());
   r.auth=await fetch(b+'/auth',{headers:{'Authorization':'Bearer fixture-token','X-Application-Key':'generic-value'}}).then(x=>x.text());
   r.wild=await fetch(b+'/wild',{headers:{'X-Application-Key':'generic-value'}}).then(x=>x.text());
   r.authWild=await fetch(b+'/auth-wild',{headers:{'Authorization':'Bearer fixture-token'}}).then(()=>false,()=>true);
   r.includeWild=await fetch(b+'/include-wild',{credentials:'include',headers:{'X-Application-Key':'generic-value'}}).then(()=>false,()=>true);
   r.include=await fetch(b+'/include',{credentials:'include',headers:{'X-Application-Key':'generic-value'}}).then(x=>x.text());
   r.omit=await fetch('/omit',{credentials:'omit',headers:{'X-Application-Key':'generic-value'}}).then(x=>x.text());
   await fetch('/report?data='+encodeURIComponent(JSON.stringify(r)));
   })().catch(e=>fetch('/report?data='+encodeURIComponent(JSON.stringify({error:String(e)}))));'''.replace('BASE',json.dumps(self.server.other))
   self.reply(('<!doctype html><script>'+js+'</script>').encode())
  elif p=='/report':self.server.report=json.loads(parse_qs(urlsplit(self.path).query)['data'][0]);self.reply()
  else:
   self.server.hits.append((p,self.headers.get('Cookie'),self.headers.get('Authorization'),self.headers.get('X-Application-Key'),self.headers.get('Sec-BoJangles-Credentials')));self.reply()
@unittest.skipUnless(os.environ.get('BOJANGLES_BROKER_RUNTIME'),'native runtime required')
class ApplicationCorsTests(unittest.TestCase):
 def test_native_headers_modes_and_denials(self):
  a=ThreadingHTTPServer(('127.0.0.1',0),Site);b=ThreadingHTTPServer(('127.0.0.1',0),Site)
  for s in (a,b):s.hits=[];s.preflights=[];s.report=None
  base=f'http://127.0.0.1:{a.server_port}/';other=f'http://127.0.0.1:{b.server_port}';a.other=other
  for s in (a,b):s.origin=base.rstrip('/');threading.Thread(target=s.serve_forever,daemon=True).start()
  root=Path(os.environ['BOJANGLES_BROKER_RUNTIME']);docs=DocumentRegistry(DEFAULT_PAGES);doc=NavigationBroker(docs).navigate(base,source=NavigationSource.OPERATOR)
  try:
   with tempfile.TemporaryDirectory() as td,SharedFramebuffer.create(640,480) as f:
    backend=WPEBackend(root/'bin/bojangles-wpe',prefix=root,extension_dir=root/'extensions',transport=BrowserCompatibleTransport(),profile_data_dir=Path(td)/'data',profile_cache_dir=Path(td)/'cache')
    try:
     backend.start(RendererStartContext(f.target(),Viewport(640,480),doc,RendererRequestBroker(docs,ContentFilter())))
     backend.load(NavigationRequest(doc.document_id,base));end=time.monotonic()+30
     while a.report is None and time.monotonic()<end:backend.poll_events();time.sleep(.05)
     self.assertEqual(a.report,dict(custom='ok',auth='ok',wild='ok',authWild=True,includeWild=True,include='ok',omit='ok'),(a.report,a.hits,b.hits,b.preflights))
     hits={x[0]:x for x in b.hits};self.assertEqual(set(hits),{'/custom','/auth','/wild','/include'})
     self.assertEqual(hits['/auth'][2],'Bearer fixture-token')
     for p in ('/custom','/auth','/wild'):self.assertIsNone(hits[p][1]);self.assertEqual(hits[p][3],'generic-value')
     self.assertIn('fixture=host-cookie',hits['/include'][1])
     self.assertIsNone(a.hits[0][1]);self.assertIsNone(a.hits[0][4])
     for x in b.preflights:self.assertIsNone(x[1]);self.assertIsNone(x[2])
     for x in b.hits:self.assertIsNone(x[4])
    finally:backend.stop()
  finally:
   for s in (a,b):s.shutdown();s.server_close()
if __name__=='__main__':unittest.main()
