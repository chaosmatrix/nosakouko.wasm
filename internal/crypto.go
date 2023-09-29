package internal

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"

	"crypto/hmac"
	_ "crypto/md5"
	_ "crypto/sha1"
	"crypto/sha256"
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
	Algorithm  string
	PrimaryKey string
	SecretFile string // optional, wasm unable read system's file, can only get the data read by js
	Site       string
	UserName   string
	Salt       string
	Round      int
	Length     int
}

func (ci *CryptoInfo) Check() (map[string]string, error) {
	errs := map[string]string{
		"algorithm": "",
		"round":     "",
		"length":    "",
	}
	var err error
	if !IsValidAlgorithm(ci.Algorithm) {
		errs["algorithm"] = fmt.Sprintf("invalid algorithm %s", ci.Algorithm)
		err = errors.New(errs["algorithm"])
	}

	if ci.Round <= 0 {
		errs["round"] = "round must larger than 0"
		err = errors.New(errs["round"])
	} else if ci.Round >= 65536 {
		errs["round"] = "round must less than 65536"
		err = errors.New(errs["round"])
	}

	if ci.Length <= 0 {
		errs["length"] = "length must larger than 0"
		err = errors.New(errs["length"])
	} else if ci.Length >= 65536 {
		errs["length"] = "length must less than 65556"
		err = errors.New(errs["length"])
	}
	return errs, err
}

func (ci *CryptoInfo) GetMask() string {
	mask := ci.Algorithm + ":" + strconv.Itoa(ci.Round) + ":" + strconv.Itoa(ci.Length)
	return mask
}

type PyS struct {
	Hashlib  string
	HashName string
	Key      string
	Data     string
	Length   int
	Round    int
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

	return strings.ToLower(strings.ReplaceAll(s[i:], "-", ""))
}

func (ci *CryptoInfo) GeneratePythonCode() string {
	tplS := `
	import {{.Hashlib}},hmac,base64
	key = "{{.Key}}"
	data = "{{.Data}}"
	length = {{.Length}}
	round = {{.Round}}
	res = ""
	for i in range(round):
		h = hmac.new(key, data, {{.Hashlib}}.{{.HashName}})
		key = h.digest()
	res = base64.urlsafe_b64encode(h.digest())[:length]
	print(res)
	`

	hmacName := strings.Split(ci.Algorithm, "-")[0]
	if go2pykdf[hmacName] == "" {
		return ""
	}

	pys := &PyS{
		Hashlib:  "hashlib",
		HashName: getPythonHashAlgorithm(ci.Algorithm),
		Key:      "PrimaryKey",
		Data:     ci.Site + ci.UserName + ci.Salt,
		Length:   ci.Length,
		Round:    ci.Round,
	}

	tpl := template.Must(template.New("tplS").Parse(tplS))

	buf := make([]byte, len(tplS))
	bw := bytes.NewBuffer(buf)

	tpl.Execute(bw, pys)

	return bw.String()
}

func (ci *CryptoInfo) GeneratePassword() (string, error) {

	bs := []byte{}
	if f, found := hmacs[ci.Algorithm]; found {
		key := []byte(ci.PrimaryKey)
		for i := 0; i < ci.Round; i++ {
			bs = f(key, []byte(ci.Site+ci.UserName+ci.Salt))
			key = bs
		}
	}

	if f, found := hkdfs[ci.Algorithm]; found {
		key := []byte(ci.PrimaryKey)
		for i := 0; i < ci.Round; i++ {
			bs = f(key, []byte(ci.Salt), []byte(ci.Site+ci.UserName))
			key = bs
		}
	}

	if f, found := pbkdf2s[ci.Algorithm]; found {
		bs = f([]byte(ci.PrimaryKey), []byte(ci.Salt+ci.Site+ci.UserName), ci.Round, ci.Length)
	}

	s := base64.URLEncoding.EncodeToString(bs)
	//dst := make([]byte, ascii85.MaxEncodedLen(len(bs)))
	//n := ascii85.Encode(dst, bs)
	//s := string(dst[:n])

	if len(s) < ci.Length {
		return s, fmt.Errorf("algorithm %s can generate password longer than %d, but length %d require", ci.Algorithm, len(s), ci.Length)
	}

	return s[:ci.Length], nil
}

func HashData(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return hex.EncodeToString(bs)
}

var hmacs = map[string]func(key []byte, data []byte) []byte{}
var hkdfs = map[string]func(key []byte, salt []byte, data []byte) []byte{}
var pbkdf2s = map[string]func(password, salt []byte, round, length int) []byte{}

func init() {
	addInternalHmac()
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

func Hmac(name string, key []byte, data []byte) []byte {
	if hmac, found := hmacs[name]; found {
		return hmac(key, data)
	}

	return nil
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

func addInternalHmac() {
	for i := crypto.MD4; i < 32; i++ {
		if !i.Available() {
			continue
		}
		hmacName := getHMACName(i.String())
		if _, exist := hmacs[hmacName]; exist {
			panic(fmt.Errorf("hmac function %s already exist", hmacName))
		} else {
			h := i.New
			hmacs[hmacName] = func(key, data []byte) []byte {
				hm := hmac.New(h, key)
				n, err := hm.Write(data)
				if n != len(data) || err != nil {
					if err != nil {
						err = errors.New("failed to write all data")
					}
					panic(err)
				}
				return hm.Sum(nil)
			}
		}

		hkdfName := getHKDFName(i.String())
		if _, exist := hkdfs[hkdfName]; exist {
			panic(fmt.Errorf("hkdf function %s already exist", hmacName))
		} else {
			h := i.New
			hkdfs[hkdfName] = func(key, salt, data []byte) []byte {
				rd := hkdf.New(h, key, salt, data)
				bs := readHKDFAll(rd)
				return bs
			}
		}

		pbkdf2Name := getPBKDF2Name(i.String())
		if _, exist := pbkdf2s[pbkdf2Name]; exist {
			panic(fmt.Errorf("pbkdf2 function %s already exist", pbkdf2Name))
		} else {
			h := i.New
			pbkdf2s[pbkdf2Name] = func(password, salt []byte, round, length int) []byte {
				return pbkdf2.Key(password, salt, round, length, h)
			}
		}
	}
}

func readHKDFAll(r io.Reader) []byte {
	buf := make([]byte, 0, 1)
	for {
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err != nil {
			break
		}
		buf = append(buf, 0)[:len(buf)]
	}
	return buf
}
