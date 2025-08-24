# aegis [![Go Reference](https://pkg.go.dev/badge/github.com/malivvan/aegis)](https://pkg.go.dev/github.com/malivvan/aegis) [![Release](https://img.shields.io/github/v/release/malivvan/aegis.svg?sort=semver)](https://github.com/malivvan/aegis/releases/latest) ![test](https://github.com/malivvan/aegis/workflows/test/badge.svg) [![Go Report Card](https://goreportcard.com/badge/github.com/malivvan/aegis)](https://goreportcard.com/report/github.com/malivvan/aegis) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

a terminal application for secret management with hardware token support

## Prerequisites

### Linux

Install the PCSC-Lite daemon and CCID driver.

Ubuntu:

    sudo apt install pcscd libccid

Arch Linux:

    sudo pacman -S pcsclite ccid
    sudo systemctl enable pcscd

### Windows

None

## Installation

```bash
go install github.com/malivvan/aegis@latest
```

## Packages
| package         | repository                                                                                                                                   | license                                      |
|-----------------|----------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| `cli`           | [github.com/aperturerobotics/cli](https://github.com/aperturerobotics/cli/tree/e94e49de9c89861f2331e136f0d7492ec6c63098)                     | [MIT](cli/LICENSE)                           |
| `scard`         | [github.com/deeper-x/gopcsc/smartcard](https://github.com/deeper-x/gopcsc/tree/2f6d14bbccd6340d0a21e27db7431d8fb0426aeb/smartcard)           | [MIT](scard/LICENSE)                         |
| `pcsc`          | [github.com/deeper-x/gopcsc/smartcard/pcsc](https://github.com/deeper-x/gopcsc/tree/2f6d14bbccd6340d0a21e27db7431d8fb0426aeb/smartcard/pcsc) | [MIT](pcsc/LICENSE)                          |
| `kdbx`          | [github.com/tobischo/gokeepasslib](https://github.com/tobischo/gokeepasslib/tree/7f3374575ee68e6aa2f1d14d0f053341912ecf5c)                   | [MIT](kdbx/LICENSE)                          |
| `mgrd`          | [github.com/awnumar/memguard](https://github.com/awnumar/memguard/tree/3152cda6d138dca44a45a0d06aa445cb2630e487)                             | [Apache-2.0 license](mgrd/LICENSE)           |
| `mgrd/memcall`  | [github.com/awnumar/memcall](https://github.com/awnumar/memcall/tree/ba2f6d61972029386765820a9bcbea79e4c1946a)                               | [Apache-2.0 license](mgrd/memcall/LICENSE)   |
| `opgp`          | [github.com/ProtonMail/gopenpgp](https://github.com/ProtonMail/gopenpgp/tree/2f846090d52deae399934a47847e8ae051a5a297)                       | [MIT](opgp/LICENSE)                          |                        
| `opgp/circl`    | [https://github.com/malivvan/aegis/opgp/circl](https://github.com/malivvan/aegis/opgp/circl/tree/c6d33e35234ebf5c4319d12ae7d77d7d17053e56)                     | [BSD 3-Clause license](opgp/circl/LICENSE)   |
| `opgp/gomime`   | [github.com/ProtonMail/go-mime](https://github.com/ProtonMail/go-mime/tree/7d82a3887f2f309b99a465c2025e74b117c3fac6)                         | [MIT](opgp/mime/LICENSE)                     |        
| `opgp/gocrypto` | [github.com/ProtonMail/go-crypto](https://github.com/ProtonMail/go-crypto/tree/3b22d8539b95b3b7e76a911053023e6ef9ef51d6)                     | [BSD-3-Clause license](opgp/xcrypto/LICENSE) |
