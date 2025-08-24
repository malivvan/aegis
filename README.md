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
| package        | repository                                                                                                                 | license                                  |
|----------------|----------------------------------------------------------------------------------------------------------------------------|------------------------------------------|
| `pcsc` `scard` | [github.com/deeper-x/gopcsc](https://github.com/deeper-x/gopcsc/tree/2f6d14bbccd6340d0a21e27db7431d8fb0426aeb)             | [MIT](scard/LICENSE) [MIT](pcsc/LICENSE) |
| `hid`          | [github.com/go-ctap/hid](https://github.com/go-ctap/hid/tree/61b5a25c7b15d1a2e93e0573b0a1a47221e85b79)                     | [Apache-2.0 license](hid/LICENSE)        |
| `kdbx`         | [github.com/tobischo/gokeepasslib](https://github.com/tobischo/gokeepasslib/tree/7f3374575ee68e6aa2f1d14d0f053341912ecf5c) | [MIT](kdbx/LICENSE)                      |
