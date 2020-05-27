"""
Apache Software License 2.0

Copyright (c) 2020, 8x8, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""

from ..backend import StoreObject
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from jinja2 import Environment, FileSystemLoader, select_autoescape
from datetime import datetime
import json


class Cert(StoreObject):
    """Object representation of a TLS certificate"""
    _common_name: str
    _body: {}
    _data: {}
    _info: {}
    _file: object
    _Jinjatemplate: Environment

    def __init__(self, common_name) -> None:
        """Constructor for Cert"""
        self._common_name = common_name
        self._body = ""
        self._info = ""
        super().__init__(common_name, self.store_path(), self._body, self._info)
        self._Jinjatemplate = Environment(loader=FileSystemLoader('templates'),trim_blocks=True,lstrip_blocks=True)
        self._cert_body = self._Jinjatemplate.get_template('cert_body.j2')
        self._cert_info = self._Jinjatemplate.get_template('cert_info.j2')
        #self.store_path()

    def convert_file_into_bytes(self, certfile:str):
        with open(certfile,'rb') as f:
            return f.read()

    def fetchthefieldsfromcert(self,certbytesdata):
        cert_info = {}
        cert_body = {}
        cert = x509.load_pem_x509_certificate(certbytesdata, default_backend())
        cert_info.update({"subject": {key.oid._name: key.value for key in cert.subject}})
        cert_info.update({"issuer": {key.oid._name: key.value for key in cert.issuer}})
        cert_info.update({"validity": {"not_before": datetime.fromtimestamp(cert.not_valid_before.timestamp()),"not_after": datetime.fromtimestamp(cert.not_valid_after.timestamp())}})
        cert_body.update({"public": cert.public_bytes(Encoding.PEM).decode('utf-8').replace('\n', '',),"private": "", "chain": ""})
        return cert_info,cert_body

    def load_cert_file(self, certfile:str):
        certdatainbytes = self.convert_file_into_bytes(certfile)
        cert_info,cert_body = self.fetchthefieldsfromcert(certdatainbytes)
        self._info = eval(self._cert_info.render(certinfo=cert_info))
        self._body = eval(self._cert_body.render(certbody=cert_body))
        self.name = self._common_name
        self.path = self.store_path()

    def store_path(self) -> str:
        """Generate a backend store path based on the certificates common name
        www.8x8.com becomes /com/8x8/www
        """
        domainsplit = self._common_name.split('.')
        return "/".join(reversed(domainsplit))

    def __str__(self) -> str:
        return self._data
