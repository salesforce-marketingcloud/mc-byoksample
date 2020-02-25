# mc-byoksample

 Generate and wrap keys using an HSM via PKCS#11 for use with Marketing Cloud BYOK.

 [BYOK Documentation](https://help.salesforce.com/articleView?id=mc_overview_byok.htm)

 

## Installation
- Install [Node.js](https://nodejs.org/)
- run `npm install` to install dependencies

## Operation
- Download your public wrapping key from the Marketing Cloud BYOK UI and save it to a file named `salesforce_rsa_pub`
- Modify the script to reference your vendor-specific PKCS#11 library and HSM login information

```
const HSM_PKCS11_LIB_FILE = 'C:/SoftHSM2/lib/softhsm2-x64.dll';
const HSM_PKCS11_LIB_NAME = 'SoftHSM';
const HSM_LOGIN_PIN = '1234';
```

- run `npm start` to run the wrapping script.  It will generate the wrapped keys and save them to the files `oaep_wrapped_intermediate_aes_key.b64` and `aes_wrapped_user_rsa_key.b64`
