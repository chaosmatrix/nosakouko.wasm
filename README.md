# nosakouko.wasm

## Abstract

**Algorithm As A Password**: Use one **Primary Key** generates all password.

[![nosakoukou](docs/Nosa_Kouko.webp)]()


## Introduction

The Algorithm and PrimaryKey are the keys to remaining the generated password safe and secure.

>
> Requirements of Algorithm:
> 1. Pure function: same input alwasy return same output
> 2. Strength: enough key space and enough length to make sure password's strength
>
> Requirements of Primary Key:
> 1. don't forget it
> 2. keep it secure
> 3. strong enough
>

### Encoder's Key Space
| Encoder | Key Space | Comment |
| -- | -- | -- |
| base64 | 65 | |
| base85/ascii85 | 85 | |

### Option Table
| Name | Private | Require | Comment |
| -- | -- | -- | -- |
| Algorithm | *  | Y | |
| Round | * | Y | |
| Length | * | Y | |
| PrimaryKey | Y | Y | |
| SecretFile | Y | Y | not implement |
| Site | * | Y | |
| UserName | * | Y | |
| Salt | * | * |  |


## Reference
1. [RFC4648 - The Base16, Base32, and Base64 Data Encodings](https://datatracker.ietf.org/doc/html/rfc4648.html)
2. [Binary-to-text encoding](https://en.wikipedia.org/wiki/Binary-to-text_encoding)
3. [Ascii85 or Base85](https://en.wikipedia.org/wiki/Ascii85)
4. [Base64](https://en.wikipedia.org/wiki/Base64)
5. [Password strength](https://en.wikipedia.org/wiki/Password_strength)
6. [Kouko Nosa - Anime Character](https://hai-furi.fandom.com/wiki/Kouko_Nosa)
