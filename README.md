# timby-zip-crypto-cli

Timby's Zip File Cryptography Command Line Tool

## Installation

```shell
$ brew install libsodium
Updating Homebrew...
==> Auto-updated Homebrew!
Updated 3 taps (homebrew/cask-versions, homebrew/core and homebrew/cask).
==> Updated Formulae
ocrmypdf                                                  qpdf

==> Downloading https://homebrew.bintray.com/bottles/libsodium-1.0.17.mojave.bottle.tar.gz
######################################################################## 100.0%
==> Pouring libsodium-1.0.17.mojave.bottle.tar.gz

$ gradle clean build
$ java -jar ./build/libs/zip-crypto-cli-1.0.0.jar serverPubKey userPubkey userId zipFileWithPath serverPrivateKey userPrivateKey passwordHash
```
