"""Large cross-origin bodies require positive Origin, CORS mode and preflight."""
import unittest
from bojangles.renderer.wpe_transport import (validate_bulk_cross_origin_post,preflight_resource_request,WPETransportError,WPEFetchedDocument,MAX_CROSS_ORIGIN_POST_BYTES,MAX_REQUEST_BODY_BYTES)

class PreflightTransport:
 def __init__(self,headers):self.headers=headers;self.calls=[]
 from bojangles.renderer.wpe_transport import WPEAllowedDataTransport
 trusted_origin_header=staticmethod(WPEAllowedDataTransport.trusted_origin_header)
 def fetch_once(self,url,**kwargs):
  self.calls.append(kwargs);return WPEFetchedDocument(url,200,'text/plain','',b'',self.headers)

class BulkUploadAuthority(unittest.TestCase):
 origin='https://example.test';target='https://upload.test/receive'
 def test_large_body_requires_exact_single_origin_and_cors_mode(self):
  good=(('Origin',self.origin),('Sec-Fetch-Mode','cors'))
  self.assertTrue(validate_bulk_cross_origin_post(good,self.origin+'/',MAX_REQUEST_BODY_BYTES))
  self.assertFalse(validate_bulk_cross_origin_post((),self.origin,MAX_CROSS_ORIGIN_POST_BYTES))
  for headers in [(),(('Origin',self.origin),),(('Origin','https://wrong.test'),('Sec-Fetch-Mode','cors')),(('Origin','null'),('Sec-Fetch-Mode','cors')),(('Origin',self.origin),('Sec-Fetch-Mode','no-cors')),good+(('Origin',self.origin),),good+(('Sec-Fetch-Mode','cors'),)]:
   with self.subTest(headers=headers):
    with self.assertRaises(WPETransportError):validate_bulk_cross_origin_post(headers,self.origin,MAX_CROSS_ORIGIN_POST_BYTES+1)
  with self.assertRaises(WPETransportError):validate_bulk_cross_origin_post(good,self.origin,MAX_REQUEST_BODY_BYTES+1)
 def test_bulk_simple_body_still_requires_anonymous_preflight(self):
  t=PreflightTransport((('Access-Control-Allow-Origin',self.origin),('Access-Control-Allow-Methods','POST')))
  preflight_resource_request(t,self.target,self.origin,'POST',(('Origin',self.origin),('Content-Type','text/plain')),credentialed=False,require_preflight=True)
  self.assertEqual(len(t.calls),1);call=t.calls[0];self.assertEqual(call['method'],'OPTIONS')
  self.assertFalse(call['send_session_cookies']);self.assertFalse(call['store_session_cookies']);self.assertFalse(call['send_authorization'])
  self.assertEqual(dict(call['request_headers']),{'Origin':self.origin,'Access-Control-Request-Method':'POST'})
 def test_origin_method_header_and_credentials_denials_remain(self):
  base=[('Access-Control-Allow-Origin',self.origin),('Access-Control-Allow-Methods','POST'),('Access-Control-Allow-Headers','x-upload')]
  for headers,credentialed in [(base[:1],False),([('Access-Control-Allow-Origin','https://wrong.test')]+base[1:],False),(base[:2],False),([('Access-Control-Allow-Origin','*')]+base[1:]+[('Access-Control-Allow-Credentials','true')],True),(base,True)]:
   with self.subTest(headers=headers,credentialed=credentialed):
    t=PreflightTransport(tuple(headers))
    with self.assertRaises(WPETransportError):preflight_resource_request(t,self.target,self.origin,'POST',(('Origin',self.origin),('X-Upload','yes')),credentialed=credentialed,require_preflight=True)
