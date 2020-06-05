import hvac
import os

os.environ['VAULT_ADDR'] = 'http://127.0.0.1:8200'
os.environ['VAULT_TOKEN'] = "xxxx"

clint = hvac.Client()


def finditer(rootpath, rootkey):
    try:
        path = rootpath
        secrets = clint.secrets.kv.list_secrets(path=path, mount_point="/certificates")
        secrets_keys = secrets.get('data').get('keys')
        if isinstance(secrets_keys, list):
            if 'cert_body' not in secrets_keys:
                for key in secrets_keys:
                    rootpaths = rootpath + key
                    finditer(rootpath=rootpaths, rootkey=key)
            else:
                cert_info_path = rootpath + "cert_info"
                cert_info_dict = clint.secrets.kv.v2.read_secret_version(path=cert_info_path, mount_point="/certificates")
                vaultpath, cn, issue_date, expiry_date = (rootpath, rootkey, \
                                                        cert_info_dict.get('data').get('data').get('validity') \
                                                          .get('not_valid_before'), \
                                                        cert_info_dict.get('data').get('data').get('validity') \
                                                            .get('not_valid_after'))
                print(vaultpath, cn, issue_date, expiry_date)
    except Exception:
        print("{} dont have any certificate info ".format(rootkey))


def main(path_to_find):
    if path_to_find == "*":
        path = "/"
    else:
        path = '/'.join(reversed(path_to_find.strip('/*').split('.'))) + "/"
    finditer(rootpath=path, rootkey="")

main(path_to_find="*")
