# nosakouko.wasm

## Abstract

**Algorithm As A Password**: Use one **Primary Key** generates all password.

[![nosakoukou](docs/Nosa_Kouko.webp)]()


## Introduction

The Algorithm and PrimaryKey are the keys to remaining the generated password safe and secure.

>
> Requirements of Algorithm:
> 1. Pure function: same input alwasy return same output
> 2. Strength: output must has enough key space and enough length to make sure password's strength
>
> Requirements of Primary Key:
> 1. don't forget it
> 2. keep it secure
> 3. strong enough
>
> Requirements of Encoder:
> 1. enough key space
> 2. all keys must Printable and Human-readable
> 

### Encoder's Key Space
| Encoder | Key Space | Comment |
| -- | -- | -- |
| base32 | 32 | human-readable but not strong enough to generate password|
| base64 | 65 | |
| base85/ascii85 | 85 | |

### Option Table
| Name | Private | Require | Default | Comment |
| -- | -- | -- | -- | -- |
| Algorithm | *  | Y | **PBKDF2-SHA-256** | |
| Round | * | Y | **13** | |
| Length | * | Y | **23** | |
| PrimaryKey | **Y** | Y | | |
| SecretFile | **Y** | Y | | not implement |
| Site | * | Y | | |
| UserName | * | Y | | |
| Salt | * | * |  | |
| Encoder | * | Y | **[Base64]** | |

[Base64]:https://en.wikipedia.org/wiki/Base64

## Reference
1. [RFC4648 - The Base16, Base32, and Base64 Data Encodings](https://datatracker.ietf.org/doc/html/rfc4648.html)
2. [Binary-to-text encoding](https://en.wikipedia.org/wiki/Binary-to-text_encoding)
3. [Ascii85 or Base85](https://en.wikipedia.org/wiki/Ascii85)
4. [Base64](https://en.wikipedia.org/wiki/Base64)
5. [ASCII - Printable characters](https://en.wikipedia.org/wiki/ASCII#Printable_characters)
6. [Password strength](https://en.wikipedia.org/wiki/Password_strength)
7. [Key derivation function](https://en.wikipedia.org/wiki/Key_derivation_function)
8. [OWASP - Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
9. [Kouko Nosa - Anime Character](https://hai-furi.fandom.com/wiki/Kouko_Nosa)
