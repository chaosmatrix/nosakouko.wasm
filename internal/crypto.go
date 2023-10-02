package internal

import (
	"bytes"
	"crypto"
	"encoding/ascii85"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"text/template"

	"crypto/hmac"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"

	"golang.org/x/crypto/argon2"
	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	_ "golang.org/x/crypto/sha3"
)

type CryptoInfo struct {
	Algorithm   string
	PrimaryKey  string
	SecretFile  string // optional, wasm unable read system's file, can only get the data read by js
	Site        string
	UserName    string
	Salt        string
	Round       int
	Length      int
	EncoderName string
}

func (ci *CryptoInfo) Check() (map[string]string, error) {
	errs := map[string]string{
		"algorithm":   "",
		"round":       "",
		"length":      "",
		"encoderName": "",
	}
	var err error
	if !IsValidAlgorithm(ci.Algorithm) {
		errs["algorithm"] = fmt.Sprintf("invalid algorithm %s", ci.Algorithm)
		err = errors.New(errs["algorithm"])
	}

	if ci.Round <= 0 {
		errs["round"] = "round must greater than 0"
		err = errors.New(errs["round"])
	} else if ci.Round >= 4294967295 {
		errs["round"] = "round must less than 4294967295"
		err = errors.New(errs["round"])
	}

	if ci.Length <= 0 {
		errs["length"] = "length must greater than 0"
		err = errors.New(errs["length"])
	} else if ci.Length >= 65536 {
		errs["length"] = "length must less than 65536"
		err = errors.New(errs["length"])
	}

	switch ci.EncoderName {
	case "base64", "ascii85":
	default:
		errs["encoderName"] = "unsupport encoder"
		err = errors.New(errs["encoderName"])
	}
	return errs, err
}

func (ci *CryptoInfo) GetMask() string {
	mask := ci.Algorithm + ":" + strconv.Itoa(ci.Round) + ":" + strconv.Itoa(ci.Length)
	return mask
}

type PyS struct {
	Hashlib      string
	HashName     string
	Key          string
	Data         string
	Length       int
	Round        int
	B64Encoder   string
	IsHMAC       bool
	IsPBKDF2HMAC bool
}

// hmac mapping
var go2pykdf = map[string]string{
	"HMAC":   "hmac",
	"HKDF":   "",
	"PBKDF2": "pbkdf2_hmac",
}

func getPythonHashAlgorithm(s string) string {
	i := 0
	if strings.HasPrefix(s, "HMAC-") {
		i = len("HMAC-")
	} else if strings.HasPrefix(s, "HKDF-") {
		i = len("HKDF-")
	} else if strings.HasPrefix(s, "PBKDF2-") {
		i = len("PBKDF2-")
	}
	s = s[i:]
	if strings.Contains(s, "SHA-") {
		s = strings.ReplaceAll(s, "-", "")
	} else if strings.Contains(s, "SHA3-") {
		s = strings.Replace(s, "-", "_", 1)
	}

	return strings.ToLower(s)
}

func (ci *CryptoInfo) GeneratePythonCode() string {
	tplS := `#
# python3
{{- if .IsHMAC }}
import {{.Hashlib}},hmac,base64
{{- else if .IsPBKDF2HMAC }}
from {{.Hashlib}} import pbkdf2_hmac
import base64
{{- end }}

password = bytes("{{.Key}}", "utf-8")
data = bytes("{{.Data}}", "utf-8")
length = {{.Length}}
round = {{.Round}}
res = b''

key = password
while len(res) < length:
	{{- if .IsHMAC }}
	for i in range(round):
		h = hmac.new(key, data, {{.Hashlib}}.{{.HashName}})
		key = h.digest()

	{{- else if .IsPBKDF2HMAC }}
	h = pbkdf2_hmac('sha256', key, data, round, length)
	key = h
	{{- end }}
	res = res + key

res = base64.{{ .B64Encoder }}(res[:length])
print(res.decode()[:length])
`

	ss := strings.Split(ci.Algorithm, "-")
	hmacName := go2pykdf[ss[0]]
	if hmacName == "" || !strings.HasPrefix(ss[1], "SHA") {
		return ""
	}

	b64encoder := ""
	switch ci.EncoderName {
	case "ascii85":
		b64encoder = "a85encode"
	case "base64":
		b64encoder = "urlsafe_b64encode"
	default:
	}

	pys := &PyS{
		Hashlib:      "hashlib",
		HashName:     getPythonHashAlgorithm(ci.Algorithm),
		Key:          "******",
		Data:         ci.Site + ci.UserName + ci.Salt,
		Length:       ci.Length,
		Round:        ci.Round,
		B64Encoder:   b64encoder,
		IsHMAC:       hmacName == "hmac",
		IsPBKDF2HMAC: hmacName == "pbkdf2_hmac",
	}

	tpl := template.Must(template.New("tplS").Parse(tplS))

	buf := new(bytes.Buffer)

	tpl.Execute(buf, pys)

	return buf.String()
}

func (ci *CryptoInfo) GeneratePassword() (string, error) {

	var bs []byte
	var err error

	if f, found := kdfs[ci.Algorithm]; found {
		bs, err = f([]byte(ci.PrimaryKey), []byte(ci.Site+ci.UserName+ci.Salt), ci.Round, ci.Length)
	} else {
		err = fmt.Errorf("invalid algorithm %s", ci.Algorithm)
		return "", err
	}

	if err != nil {
		return "", err
	}

	var s string
	switch ci.EncoderName {
	case "base64":
		s = base64.URLEncoding.EncodeToString(bs)
	case "ascii85":
		dst := make([]byte, ascii85.MaxEncodedLen(len(bs)))
		n := ascii85.Encode(dst, bs)
		s = string(dst[:n])
	default:
		err = fmt.Errorf("invalid encoder %s", ci.EncoderName)
		return "", err
	}

	if len(s) < ci.Length {
		return s, fmt.Errorf("algorithm %s can generate password longer than %d, but length %d require", ci.Algorithm, len(s), ci.Length)
	}

	return s[:ci.Length], nil
}

var kdfs = map[string]func(password []byte, salt []byte, round int, length int) ([]byte, error){
	"argon2id": argon2id,
	"argon2i":  argon2i,
	"scrypt":   scryptKDF,
}

func init() {
	initBuiltinKDFS()
}

func IsValidAlgorithm(s string) bool {
	if _, found := kdfs[s]; found {
		return found
	}
	return false
}

func GetAlgorithms() []string {
	res := make([]string, len(kdfs))
	i := 0
	for k := range kdfs {
		res[i] = k
		i++
	}
	return res
}

func initBuiltinKDFS() {
	kdfprefixs := []string{"HMAC-", "HKDF-", "PBKDF2-"}
	for i := crypto.MD4; i < 32; i++ {
		if !i.Available() {
			continue
		}
		for _, ps := range kdfprefixs {
			name := ps + i.String()
			if _, exist := kdfs[name]; exist {
				panic(fmt.Errorf("kdf %s already exist", name))
			} else {
				h := i.New
				switch ps {
				case "HMAC-":
					kdfs[name] = func(password, salt []byte, round, length int) ([]byte, error) {
						return hmacKey(h, password, salt, round, length)
					}
				case "HKDF-":
					kdfs[name] = func(password, salt []byte, round, length int) ([]byte, error) {
						return hkdfKey(h, password, salt, round, length)
					}
				case "PBKDF2-":
					kdfs[name] = func(password, salt []byte, round, length int) ([]byte, error) {
						return pbkdf2Key(h, password, salt, round, length)
					}
				}
			}
		}
	}
}

func hmacKey(h func() hash.Hash, password []byte, salt []byte, round int, length int) (key []byte, err error) {

	key = make([]byte, length)

	k := password
	for l := 0; l < len(key); {
		for i := 0; i < round; i++ {
			hm := hmac.New(h, k)
			n, err := hm.Write(salt)
			if n != len(salt) || err != nil {
				if err != nil {
					err = errors.New("failed to write all data")
				}
				return []byte{}, err
			}
			k = hm.Sum(nil)
		}
		copy(key[l:], k)
		l += len(k)
	}
	return
}

func hkdfKey(h func() hash.Hash, password []byte, salt []byte, round int, length int) (key []byte, err error) {

	key = password
	buf := make([]byte, length)
	for i := 0; i < round; i++ {
		rd := hkdf.New(h, key, salt, nil)
		n, err := rd.Read(buf)
		if n != length || err != nil {
			if err == nil {
				err = fmt.Errorf("require length %d, but only %d bytes read", length, n)
			}
			return []byte{}, err
		}
		key = buf
	}
	return
}

func pbkdf2Key(h func() hash.Hash, password []byte, salt []byte, round int, length int) ([]byte, error) {
	return pbkdf2.Key(password, salt, round, length, h), nil
}

// argon2
func argon2id(password []byte, salt []byte, round int, length int) ([]byte, error) {
	return argon2.IDKey(password, salt, uint32(round), 2*1024, 1, uint32(length)), nil
}

func argon2i(password []byte, salt []byte, round int, length int) ([]byte, error) {
	return argon2.Key(password, salt, uint32(round), 2*1024, 1, uint32(length)), nil
}

func scryptKDF(password []byte, salt []byte, round int, length int) ([]byte, error) {
	return scrypt.Key(password, salt, 32768, round, 1, length)
}
