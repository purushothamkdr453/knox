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
limitations under the License.
"""

import sys
import json
import hvac
import boto3
from botocore.exceptions import ClientError, EndpointConnectionError
from dynaconf import settings
from datetime import datetime, time
from jinja2 import Template, Environment, FileSystemLoader
from loguru import logger

from .store_engine import StoreEngine
from .store_object import StoreObject
from ..certificate import Cert
from ..certificate import AWSCert
from .store_vault import VaultStoreEngine


class ACMStoreEngine(StoreEngine):
    """
    ACMStoreEngine Class
    CRUD operations for Aws Certificate Manager
    """

    __AwsErrors = (ClientError, EndpointConnectionError)
    __session: boto3.session.Session

    def __init__(self, profile_name=None, region=None):
        super().__init__()
        self.profile_name = profile_name if profile_name is not None else settings.AWS_PROFILE
        self.region = region if region is not None else settings.AWS_REGION
        self.CertArn = None
        self.__path = None
        self._jinja = Environment(loader=FileSystemLoader('templates'))
        self._tmpl_tags = self._jinja.get_template('tags_template.js')
        if self.initialize():
            logger.debug(f'Connected to ACM')
        else:
            logger.error(f'No AWS profiles found')
            sys.exit(1)

    def initialize(self) -> None:
        self.__session = boto3.Session(profile_name=self.profile_name, region_name=self.region)
        return self.__session.available_profiles().len() > 0

    def find(self, pattern: str) -> [AWSCert]:
        certs = []
        try:
            acm_res = self.__session.client('acm').list_certificates(
                CertificateStatuses=['ISSUED'],
                MaxItems=123
            )
            acm_certs = acm_res.get('CertificateSummaryList')
            for acm in acm_certs:
                domainname = acm['DomainName']
                arn = acm['CertificateArn']
                if domainname == pattern:
                    certs.append(self.get(name=domainname, arn=arn))

        except self.__AwsErrors as e:
            logger.error(f'[AWSCert]: Exception listing certificates from ACM {e}')
            sys.exit(1)
        else:
            return certs

    def get(self, name: str, arn: str) -> AWSCert:
        try:
            acm_res = self.__session.client('acm').get_certificate(
                CertificateArn=arn
            )
            cert = AWSCert(common_name=name)
            cert.public = acm_res.get('Certificate')
            if hasattr(acm_res, 'CertificateChain'):
                cert.chain = acm_res.get('CertificateChain')

        except self.__AwsErrors as e:
            logger.error(f'[AWSCert]: Exception listing certificates from ACM {e}')
            sys.exit(1)
        return cert

    def read(self, name: str, path: str = None, type=None) -> StoreObject:
        certs = self.find(name)
        for cert in certs:
            if cert.name == name:
                return cert

    def write(self, cert: AWSCert) -> bool:
        """ ACM Store Engine Write the certificate to specified region and account

            :param cert: The StoreObject to persist in AWS ACM Store
            :type cert: Cert
            :return: bool

        """
        logger.trace(f'[ACMStoreEngine]:\nPUB:\n{cert.public}\nKEY:\nREDACTED\nCHAIN:\n{cert.chain}\n')

        try:
            acm_res = self.__session.client('acm').import_certificate(
                Certificate=cert.public,
                PrivateKey=cert.private,
                CertificateChain=cert.chain,
                Tags=self._tmpl_tags.render(cert=cert)
            )
            cert.arn = acm_res.get('CertificateArn')
            cert.add_delivery(acm_res)
            logger.info(
                f'[ACMStoreEngine]: Certificate uploaded:\n'
                f'Region: {self.region}\n'
                f'Account: {self.profile_name}\n'
                f'CertARN: {cert.arn}')
            return True

        except self.__AwsErrors as e:
            logger.error(f'[ACMStoreEngine]: Exception listing certificates from ACM {e}')
            sys.exit(1)

    # Private method
#    def __delivery_info(self):
#        """ ACM Store delivery information """
#        time_utc_now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
#        tmpl = Environment(loader=FileSystemLoader('templates'))
#        tmpl_delivery = tmpl.get_template('delivery_template.js')
#        output = tmpl_delivery.render(time_utc_now=time_utc_now, region=self.region, profile=self.profile_name,
#                                      certarn=self.CertArn)
#
#        client = self.__vault_client
#        mp = self.__vault_mount
#        full_path = self.__path + "/delivery_info"
#
#        try:
#            client.secrets.kv.v2.create_or_update_secret(path=full_path, mount_point=mp, secret=json.loads(output))
#
#        except Exception as e:
#            logger.error(f'[ACMStoreEngine]: Failed to write delivery_info to Vault {e}')
