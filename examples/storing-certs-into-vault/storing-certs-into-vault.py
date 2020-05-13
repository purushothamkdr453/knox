import hvac
import os
import json
import subprocess
import sys

client = hvac.Client(url=os.environ['VAULT_ADDR'],token=os.environ['VAULT_TOKEN'])

def askforrootmountpoint():
    rootmountpoint = input("Please enter the root mount point with out slash the end for example learning not learning/: ")
    return rootmountpoint

def checkrootmountpointexitsornot(mount_point):
    process = subprocess.Popen(['curl','--silent','--header','X-Vault-Token:'+os.getenv('VAULT_TOKEN'),'http://127.0.0.1:8200/v1/sys/mounts'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True,universal_newlines=True)
    output,err = process.communicate()
    enabledsecretslist = json.loads(output)
    if mount_point+"/" in enabledsecretslist['data'].keys():
        return True
    else:
        return False

def createtherootmountpointifitdoesntexist(mountpointexistornot,mount_point):
    if mountpointexistornot:
        pass
    else:
        print("root mountpoint doesnt exist hence creating the same")
        enablesecretengine = subprocess.Popen(['curl','--silent','--header','X-Vault-Token:'+os.getenv('VAULT_TOKEN'),'--request','POST','--data','{ "type": "kv-v2" }','http://127.0.0.1:8200/v1/sys/mounts'+"/"+mount_point],stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True,universal_newlines=True)
        out,err = enablesecretengine.communicate()

def readthejson():
    with open(sys.argv[1]) as f:
        data = json.load(f)
        return data['cert_info']['subject']['common_name'],data['cert_body'],data['cert_info']

def createsecretpathforthedomain(cn):
    domainsplit = cn.split('.')
    return "/".join(reversed(domainsplit))

def authenticationcheck():
    authcheck = client.is_authenticated()
    if authcheck:
       print("Authentication success")
    else:
       raise Exception("Vault authentication failed")

def createpathandinsertsecretcontent(secretpath,cert_body,cert_info,rootmountpoint):
    try:
        client.secrets.kv.v2.create_or_update_secret(path=secretpath+"/cert_body",mount_point=rootmountpoint,secret=cert_body)
        client.secrets.kv.v2.create_or_update_secret(path=secretpath+"/cert_info",mount_point=rootmountpoint,secret=cert_info)
        print("Certs are stored into the vault")
    except Exception as e:
        print(e)
    
def main():
    rootmountpoint = askforrootmountpoint()
    mountpointexistornot = checkrootmountpointexitsornot(rootmountpoint)
    createtherootmountpointifitdoesntexist(mountpointexistornot,rootmountpoint)
    common_name,cert_body,cert_info=readthejson()
    secretpath = createsecretpathforthedomain(common_name)
    authenticationcheck()
    createpathandinsertsecretcontent(secretpath,cert_body,cert_info,rootmountpoint)

if __name__  == "__main__":
    main()
