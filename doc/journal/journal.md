# Journal

## 2018.12.12

* debugged why auth data is still missing
*         node.put("attestation", "direct"); was missing apparently
* tested against dev.webauthn.demo instead of localhost
* lots of refactoring. Done to step 13

## 2018.12.10

* created local ssl cert
* searched for https server that can be launched from terminal
* set up stuff

## 2018.12.03 Project Meeting

### 2. Tasks

* check NFC on android --> make it work
* Login

## 2018.12.01 - 2018.12.03

Created first draft of register. Client side heavily leaned on webauthn-demo from Fido-Alliance. Currently parsing of answer is done manually. Should aim for some kind of Library. So far none really jumps out. Maybe Yubico Library.

Browser compatibility not yet tested...

### Issues

* No easy to use libraries
* Documentation not easy to follow
* HTTPS required for certain things

## 2018.11.24

Completed demo from Fido-Alliance at <https://github.com/fido-alliance/webauthn-demo>
Important: Doesn't work in chrome.

## 2018.11.17

asd

## 2018.11.12 Project Meeting

### 1. Tasks

* Setting up Webclient with FIDO2 Auth
* checking browser compatibility
* checking authenticator requirements
