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
limitations under the License. """
import sys

import click
import pkg_resources
from loguru import logger

from .certificate import Cert  # noqa: F401
from .config import Conf
from .knox import Knox


@click.group()
@click.option("--log", "-l",
              type=click.Choice(['TRACE',
                                 'DEBUG',
                                 'INFO',
                                 'SUCCESS',
                                 'WARNING',
                                 'ERROR',
                                 'CRITICAL']),
              default='INFO',
              show_default=True,
              help="Sets the level of logging displayed")
@click.option('--debug/--no-debug', default=False, help="Display log output to console")
@click.version_option(version=pkg_resources.get_distribution('knox').version)
@click.pass_context
@logger.catch()
def cli(ctx, debug, log):
    """Utilities for managing and storing TLS certificates using backing store (Vault)."""
    ctx.ensure_object(dict)
    ctx.obj['DEBUG'] = debug
    ctx.obj['LOG_LEVEL'] = log
    logger.remove()
    if debug:
        logger.add(sys.stdout,
                   format="{time} {level: >9} {level.icon} {message}",
                   filter=Conf.log_filter,
                   level=f"{log}",
                   colorize=True)
    else:
        logger.add(sys.stderr,
                   format="{time} {level: >9} {level.icon} {message}",
                   filter=Conf.log_filter,
                   level=f"{log}",
                   colorize=True)
    logger.info(f' Log level set to {ctx.obj["LOG_LEVEL"]}')


@cli.group(no_args_is_help=True)
@click.option("--type", "-t",
              type=click.Choice(['PEM', 'DER', 'PFX']),
              default='PEM',
              show_default=True)
@click.option("--pub", help="Public key file")
@click.option("--chain", help="Intermediate chain")
@click.option("--key", help="Private key file")
@click.pass_context
@logger.catch()
def cert(ctx, type, pub, key, chain=None):
    """Certificate utilities.

    NAME is the common name for the certificate. i.e. www.example.com
    """
    ctx.obj['CERT_PUB'] = pub
    ctx.obj['CERT_CHAIN'] = chain
    ctx.obj['CERT_KEY'] = key
    ctx.obj['CERT_TYPE'] = type


@cert.command(no_args_is_help=True)
@click.argument("name")
@click.pass_context
@logger.catch()
def save(ctx, name):
    """Store an existing certificate
    """
    ctx.obj['CERT_NAME'] = name
    pub = ctx.obj['CERT_PUB']
    key = ctx.obj['CERT_KEY']
    chain = ctx.obj['CERT_CHAIN']
    certtype = ctx.obj['CERT_TYPE']

    knox = Knox(ctx.obj['LOG_LEVEL'])
    certificate = Cert(knox.settings, common_name=name)
    certificate.load(pub=pub,
                     key=key,
                     chain=chain,
                     certtype=certtype)
    knox.store.save(certificate)


@cert.command(no_args_is_help=True)
@click.argument("name")
@click.pass_context
@logger.catch()
def get(ctx, name):
    """Retrieve an existing certificate for a given common name from the store
    """
    ctx.obj['CERT_NAME'] = name
    knox = Knox(ctx.obj['LOG_LEVEL'])
    certificate = Cert(knox.settings, common_name=name)
    certificate.type = ctx.obj['CERT_TYPE']
    certificate = knox.store.get(certificate.store_path(), name=name, type=certificate.type)
    with open(certificate.name+"-pub.pem", "w") as pubf:
        pubf.write(certificate.body['public'])
    with open(certificate.name+"-key.pem", "w") as keyf:
        keyf.write(certificate.body['private'])
    with open(certificate.name+"-chain.pem", "w") as chainf:
        chainf.write(certificate.body['chain'])


@cert.command(no_args_is_help=True)
@click.argument("name")
@click.pass_context
@logger.catch()
def gen(ctx, name):
    """Create and store a new certificate for a given common name
    """
    ctx.obj['CERT_NAME'] = name

    knox = Knox(ctx.obj['LOG_LEVEL'])
    certificate = Cert(knox.settings, common_name=name)
    certificate.generate()
    knox.store.save(certificate)


@cli.command(no_args_is_help=True)
@click.option("-f", "--find", help="Find certificate by common name")
@click.argument("name")
@click.pass_context
@logger.catch()
def store(ctx, find, name) -> dict:
    """Store commands. Given a certificate NAME perform the store operation.

    NAME can be similar to a full file path or the certificates common name.
    i.e. www.example.com becomes /com/example/www/www.example.com when stored.

    """
    ctx.obj['STORE_FIND'] = find
    knox = Knox(ctx.obj['LOG_LEVEL'])
    if find:
        certificate = knox.store.find(Cert.to_store_path(name), name=name)  # noqa F841
        # save certificate_public_key.pem
        # save certificate_private_key.pem
        # save certificate_chain.pem

    return ctx


def main():
    cli(prog_name="knox", obj={})


if __name__ == "__main__":
    main()
