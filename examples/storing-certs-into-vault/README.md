Overview of Vault:
------------------------------

Vault is a tool for securely accessing secrets. A secret is anything that you want to tightly control access to, such as API keys, 
passwords, or certificates. Vault provides a unified interface to any secret, while providing tight access control and recording a detailed audit log.


what does storing-certs-into-vault.py do?
-----------------------------------------

This script assumes that vault setup is already in place, expects VAULT_TOKEN,VAULT_ADDR environement varibles are already set. These are used for making a 
connection to vault. Besides Script expects an argumet ie certfile(cert.json in this scenario). Python scripts reads the "common_name" field  from cert file 
and creates the directory structure in vault,"certbody" and "certinfo" data will be pulled certfile and then stores them in the created directory structure.


for example if common_name is 8x8.cloud.staging.com then directory structure will be -> /com/staging/cloud/8x8

certbody & certinfo will be stored under /com/staging/cloud/8x8

Script Execution:
----------------------------------------

python storing-certs-into-vault.py cert.json
