package main

import (
	"fmt"
	"nosakouko/internal"
	"strconv"
	"syscall/js"
)

func GeneratePassword() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {

		var err error

		obj := args[len(args)-1]

		round := 0
		lengthx := 0
		if s := obj.Get("round").String(); s != "" {
			round, err = strconv.Atoi(s)
			if err != nil {
				panic(err)
			}
		}
		// length is keyword in js
		if s := obj.Get("lengthx").String(); s != "" {
			lengthx, err = strconv.Atoi(s)
			if err != nil {
				panic(err)
			}
		}

		ci := internal.CryptoInfo{
			Algorithm:   obj.Get("algorithm").String(),
			PrimaryKey:  obj.Get("primaryKey").String(),
			SecretFile:  obj.Get("secretFile").String(),
			Site:        obj.Get("site").String(),
			UserName:    obj.Get("userName").String(),
			Salt:        obj.Get("salt").String(),
			Round:       round,
			Length:      lengthx,
			EncoderName: obj.Get("encoderName").String(),
		}

		errs, nerr := ci.Check()
		for en, ev := range errs {
			js.Global().Get("err_"+en).Set("textContent", ev)
		}
		if nerr != nil {
			return nil
		}

		//fmt.Printf("%#v\n", ci)
		//fmt.Printf("%v\n", internal.GetAlgorithms())

		// Promise handler
		handler := js.FuncOf(func(this js.Value, args []js.Value) any {
			resolve := args[0]
			reject := args[1]

			if err != nil {
				js.Global().Get("ans_password").Set("textContent", fmt.Sprintf("Error: %s", err.Error()))
				reject.Invoke(err.Error())
				return nil
			}

			// in js, async/await make sure this code returen
			go func() {

				password, err := ci.GeneratePassword()

				if err != nil {
					js.Global().Get("ans_stars").Set("textContent", err.Error())
					js.Global().Get("ans_password").Set("textContent", err.Error())
					js.Global().Get("ans_crypto_mask").Set("textContent", "")
					js.Global().Get("ans_python_code").Set("textContent", "")
				} else {
					js.Global().Get("ans_stars").Set("textContent", "**********************")
					js.Global().Get("ans_password").Set("textContent", password)
					js.Global().Get("ans_crypto_mask").Set("textContent", ci.GetMask())
					js.Global().Get("ans_python_code").Set("textContent", ci.GeneratePythonCode())
				}
				// Resolve the Promise
				resolve.Invoke(password)
			}()

			// Promise handler always return nil
			return nil
		})

		js.Global().Get("ans_password").Set("textContent", "password generating ...")

		// return Promise object about the handler
		// in js, use async/await to make sure handler(promise) execute
		return js.Global().Get("Promise").New(handler)
	})
}

func main() {

	js.Global().Set("GeneratePassword", GeneratePassword())
	select {}
}
