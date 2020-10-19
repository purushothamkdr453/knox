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
import ast
import enum
import json
from binascii import hexlify

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from dynaconf import LazySettings
from jinja2 import Environment
from jinja2 import FileSystemLoader
from loguru import logger

from ..backend import StoreObject
from .cert_engine import CertDnsEngine


class Cert(StoreObject):
    """Object representation of a TLS certificate"""
    _body: str  #: String representation of private, chain and public portions of certificate as a map/json
    _info: str  #: Certificate details
    _data: {}   #: Combined body and info map
    _file: object
    _x509: x509
    _common_name: str
    _type: str  #: Certificate type identifier
    _jinja: Environment

    class CertTypes(enum.Enum):
        PEM = 1
        DER = 2
        PFX = 3

        @classmethod
        def valid(cls, name) -> bool:
            return any(x for x in cls if x.name == name)

    PEM = CertTypes.PEM
    DER = CertTypes.DER
    PFX = CertTypes.PFX

    def __init__(self, settings: LazySettings, common_name=None) -> None:
        """Constructor for Cert"""
        self._settings = settings
        self._common_name = self.valid_name(common_name)
        self._body = ""
        self._info = ""
        self._type = ""
        super().__init__(name=self._common_name, path=self.store_path(), body=self._body, info=self._info)
        self._jinja = Environment(loader=FileSystemLoader('templates'))
        self._tmpl_body = self._jinja.get_template('body_template.js')
        self._tmpl_info = self._jinja.get_template('info_template.js')
        self._tmpl_data = self._jinja.get_template('data_template.js')

    def load_x509(self, path: str) -> None:
        """Given path to PEM x509 read in certificate

            :param path: File path to x509 PEM file
            :type path: str
        """
        self.type = Cert.PEM.name

        with open(path, mode='r+', encoding='utf-8') as fp:
            self._file = fp.read()
            self._x509 = x509.load_pem_x509_certificate(bytes(self._file, 'utf-8'), default_backend())

        """Generate data structures using custom Jinja2 templates"""
        self._info = ast.literal_eval(self._tmpl_info.render(cert=self))
        self._body = ast.literal_eval(self._tmpl_body.render(cert=self))
        self._data = ast.literal_eval(self._tmpl_data.render(cert=self))

        """Ensure raw file contents in public key, Jinja2 fails to parse if there are CR LF"""
        self.public = self._file

        """Match the objects common name to the true common name from the certificate and
        swap out '*' astrix for the keyword wildcard
        """
        self._common_name = self.valid_name(self._data['cert_info']['subject']['commonName'])
        self.name = self.valid_name(self._common_name)

        """Ensure path is the inverse of the true cert common name"""
        self.path = self.store_path()

    def load(self, pub: str, key: str, certtype: enum.Enum = PEM, chain: str = None) -> None:
        """Read in components of a certificate, given filename paths for each

            :param pub: File name of public portion of key
            :type pub: str
            :param key: File name of private portion of key
            :type key: str
            :param chain: File name of intermediate certificates. Optional as they could be in pub
            :type chain: str
            :param certtype: Enum of certificate types [PEM=1, DER=2]
            :type certtype: Enum
        """
        if certtype == Cert.PEM.name:
            self.load_x509(pub)

        with open(key, mode="r") as key_fp:
            self._body['cert_body']['private'] = key_fp.read()

        if chain:
            with open(chain, mode="r") as chain_fp:
                self._body['cert_body']['chain'] = chain_fp.read()

        self._data['cert_body'] = self._body['cert_body']

    @classmethod
    def valid_name(cls, value: str) -> str:
        """Some engines might have problems with astrix, as they are used for glob searching and or RBAC.
        Replace it with the key word 'wildcard'. This does not affect the actual certificate."""
        return value.replace('*', 'wildcard')

    def subject(self) -> str:
        """Return the certificate subject details"""
        return json.dumps({attr.oid._name: attr.value for attr in self._x509.subject}, indent=8)

    @property
    def type(self) -> str:
        return self._type

    @type.setter
    def type(self, value: str) -> None:
        if Cert.CertTypes.valid(value):
            self._type = value

    def issuer(self) -> str:
        """Return the certificate issuer details"""
        return json.dumps({attr.oid._name: attr.value for attr in self._x509.issuer}, indent=8)

    def validity(self) -> str:
        """Return the certificates dates of validity"""
        cert = self._x509
        return json.dumps({
            'not_valid_before': f'{cert.not_valid_before}',
            'not_valid_after': f'{cert.not_valid_after}',
        }, indent=8)

    def key_details(self) -> str:
        """Return characteristics of key used to generate the certificate"""
        cert = self._x509
        public_key = self._x509.public_key()
        key_info = {'size': public_key.key_size}
        if isinstance(public_key, rsa.RSAPublicKey):
            key_type = 'RSA'
        elif isinstance(public_key, dsa.DSAPublicKey):
            key_type = 'DSA'
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_type = 'ECC'
            key_info['curve'] = public_key.curve.name
        else:
            raise ValueError('Invalid key type.')
        key_info['type'] = key_type
        return json.dumps({
            'version': cert.version.name,
            'fingerprint_sha256': hexlify(cert.fingerprint(hashes.SHA256())).decode(),
            'serial_number': f'{cert.serial_number}',
            'key': key_info
        }, indent=8)

    @staticmethod
    def to_store_path(common_name: str) -> str:
        """Generate a backend store path based on the certificates common name
        www.example.com becomes /com/example/www

            :return: str
        """
        domainsplit = common_name.split('.')
        return "/"+"/".join(reversed(domainsplit))

    def store_path(self) -> str:
        return self.to_store_path(self._common_name)

    def __str__(self) -> str:
        return json.dumps(self._data, indent=4)

    @property
    def private(self) -> str:
        """Unless its a dict, its not loaded yet"""
        if isinstance(self._body, dict):
            return json.dumps(self._body['cert_body']['private']).replace('\n', '')
        else:
            return ""

    @property
    def chain(self) -> str:
        """Unless its a dict, its not loaded yet"""
        if isinstance(self._body, dict):
            return json.dumps(self._body['cert_body']['chain']).replace('\n', '')
        else:
            return ""

    @chain.setter
    def chain(self, value) -> None:
        if isinstance(self._body, dict):
            self._body['cert_body']['chain'] = value
            self._data['cert_body']['chain'] = value

    @property
    def public(self) -> str:
        """Convenience method for Jinja2 templates. Jinja2 does not process the string if it has carriage returns."""
        if self.type == Cert.PEM.name:
            return self._x509.public_bytes(Encoding.PEM).decode('utf-8').replace('\n', '')
        else:
            raise CertUnsupportedTypeException(type=self.type)

    @public.setter
    def public(self, value: str) -> None:
        if isinstance(self._body, dict):
            self._body['cert_body']['public'] = value
            self._data['cert_body']['public'] = value

    def info(self) -> str:
        return json.dumps(self._info['cert_info'], indent=4)

    def body(self) -> str:
        return json.dumps(self._body['cert_body'], indent=4)

    @property
    def data(self) -> str:
        """Content to persist, typically JSON"""
        return self._data

    def generate(self) -> None:
        """ Generate certificate for a given common name"""
        try:
            cde = CertDnsEngine(self._settings)
            certfile, chainfile, privkey = cde.call_provider(self._common_name)
            self.load(pub=certfile, key=privkey, chain=chainfile, certtype=Cert.PEM.name)
        except Exception:
            logger.error(f'Failed to generate certificate {self._common_name}')


class CertUnsupportedTypeException(Exception):
    """Exception raised for an unrecognized certificate type"""

    def __init__(self, type: str = None) -> None:
        self.type = type
        super().__init__()

    def __str__(self):
        return f'Unsupported certificate type: {self.type}'
