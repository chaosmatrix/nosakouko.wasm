package internal

import (
	"bytes"
	"crypto"
	"encoding/ascii85"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/template"

	"crypto/hmac"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"

	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	_ "golang.org/x/crypto/sha3"
	//_ "golang.org/x/crypto/md4"
	//_ "golang.org/x/crypto/ripemd160"
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
	} else if ci.Round >= 65536 {
		errs["round"] = "round must less than 65536"
		err = errors.New(errs["round"])
	}

	if ci.Length <= 0 {
		errs["length"] = "length must greater than 0"
		err = errors.New(errs["length"])
	} else if ci.Length >= 65536 {
		errs["length"] = "length must less than 65556"
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

key = bytes("{{.Key}}", "utf-8")
data = bytes("{{.Data}}", "utf-8")
length = {{.Length}}
round = {{.Round}}
res = ""

{{- if .IsHMAC }}
for i in range(round):
	h = hmac.new(key, data, {{.Hashlib}}.{{.HashName}})
	key = h.digest()
{{- else if .IsPBKDF2HMAC }}
h = pbkdf2_hmac('sha256', key, data, round, length)
key = h
{{- end }}

res = base64.{{ .B64Encoder }}(key)[:length]
print(res.decode())
`

	ss := strings.Split(ci.Algorithm, "-")
	hmacName := go2pykdf[ss[0]]
	shaName := ss[1]
	if hmacName == "" || !strings.HasPrefix(shaName, "SHA") {
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

	bs := []byte{}
	var err error
	if f, found := hmacs[ci.Algorithm]; found {
		key := []byte(ci.PrimaryKey)
		for i := 0; i < ci.Round; i++ {
			bs, err = f(key, []byte(ci.Site+ci.UserName+ci.Salt))
			if err != nil {
				return "", err
			}
			key = bs
		}
	}

	if f, found := hkdfs[ci.Algorithm]; found {
		key := []byte(ci.PrimaryKey)
		for i := 0; i < ci.Round; i++ {
			bs, err = f(key, []byte(ci.Salt), []byte(ci.Site+ci.UserName), ci.Length)
			if err != nil {
				return "", err
			}
			key = bs
		}
	}

	if f, found := pbkdf2s[ci.Algorithm]; found {
		bs, err = f([]byte(ci.PrimaryKey), []byte(ci.Site+ci.UserName+ci.Salt), ci.Round, ci.Length)
		if err != nil {
			return "", err
		}
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
	}

	if len(s) < ci.Length {
		return s, fmt.Errorf("algorithm %s can generate password longer than %d, but length %d require", ci.Algorithm, len(s), ci.Length)
	}

	return s[:ci.Length], nil
}

var hmacs = map[string]func(key []byte, data []byte) ([]byte, error){}
var hkdfs = map[string]func(key []byte, salt []byte, data []byte, length int) ([]byte, error){}
var pbkdf2s = map[string]func(password, salt []byte, round, length int) ([]byte, error){}

func init() {
	initBuiltinKDFS()
}

func IsValidAlgorithm(s string) bool {
	if _, found := hmacs[s]; found {
		return found
	}
	if _, found := hkdfs[s]; found {
		return found
	}
	if _, found := pbkdf2s[s]; found {
		return found
	}
	return false
}

func GetAlgorithms() []string {
	res := make([]string, len(hmacs)+len(hkdfs)+len(pbkdf2s))
	i := 0
	for k, _ := range hmacs {
		res[i] = k
		i++
	}
	for k, _ := range hkdfs {
		res[i] = k
		i++
	}
	for k, _ := range pbkdf2s {
		res[i] = k
		i++
	}
	return res
}

func getHMACName(s string) string {
	return "HMAC-" + s
}

func getHKDFName(s string) string {
	return "HKDF-" + s
}

func getPBKDF2Name(s string) string {
	return "PBKDF2-" + s
}

func initBuiltinKDFS() {
	for i := crypto.MD4; i < 32; i++ {
		if !i.Available() {
			continue
		}
		hmacName := getHMACName(i.String())
		if _, exist := hmacs[hmacName]; exist {
			panic(fmt.Errorf("hmac function %s already exist", hmacName))
		} else {
			h := i.New
			hmacs[hmacName] = func(key, data []byte) ([]byte, error) {
				hm := hmac.New(h, key)
				n, err := hm.Write(data)
				if n != len(data) || err != nil {
					if err != nil {
						err = errors.New("failed to write all data")
					}
					return []byte{}, err
				}
				return hm.Sum(nil), nil
			}
		}

		hkdfName := getHKDFName(i.String())
		if _, exist := hkdfs[hkdfName]; exist {
			panic(fmt.Errorf("hkdf function %s already exist", hmacName))
		} else {
			h := i.New
			hkdfs[hkdfName] = func(key, salt, data []byte, length int) ([]byte, error) {
				rd := hkdf.New(h, key, salt, data)
				bs := make([]byte, length)
				n, err := rd.Read(bs)
				if n != length || err != nil {
					if err == nil {
						err = fmt.Errorf("require length %d, but only %d bytes read", length, n)
					}
					return []byte{}, err
				}
				return bs, nil
			}
		}

		pbkdf2Name := getPBKDF2Name(i.String())
		if _, exist := pbkdf2s[pbkdf2Name]; exist {
			panic(fmt.Errorf("pbkdf2 function %s already exist", pbkdf2Name))
		} else {
			h := i.New
			pbkdf2s[pbkdf2Name] = func(password, salt []byte, round, length int) ([]byte, error) {
				return pbkdf2.Key(password, salt, round, length, h), nil
			}
		}
	}
}
