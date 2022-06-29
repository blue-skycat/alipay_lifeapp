/**
  @auther: blue-skycat
  @date: 2022/6/28
  @note:
**/
package controllers

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	encodingxml "encoding/xml"
	"errors"
	"fmt"
	beego "github.com/beego/beego/v2/server/web"
	"github.com/go-pay/gopay"
	"github.com/go-pay/gopay/alipay"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"hash"
	"io/ioutil"
	"log"
	"strings"
)

type AliopenController struct {
	beego.Controller
}
type PKCSType uint8

const (
	Ali_public_key            = "MIIBIjANBgkqhkiG9w0BAQEevyY0/OCLliGoINTi5g4l6PWOok2Y/UaqVszn90pM2Z1IfJsv77L3UMdrt68rpB27Pcb0BHmW/jTV1mD7Sns48ipqPVYgZcr4m+zDrRSGuoWgz5DJInIoJsRBxeBtYHPfGLQMWf6SpouKsPm8AGMx7BY56jGUp5x1oJ5WW60gVAJqMulywTk07zhEXUlu6ATjLoHNbok2KCwFRwILYeha58/qtE+j/qkdFq4P4RwkBOi3wmFYU0Qs4f/iutR6QpGJXbYzc/C4eUSkLLmwIDAQAB"
	Self_public_key           = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiZLlVwbYW2vAxMXwHVJ+euUCTw2jsG932o/xk1xWY0po+PWaki/2y1pnWn2wJivGcWA17dyqEqG26kOFC7/PJIsN5epvnGjopRdq7zhDvEjq/89wulQIWrUiJN1iRNTMNZQg1/TJv5ls62ahBlYIbO7jlW4wPfVO94TNJOLDfpEcLNzR01laQFRHpMSuXFCsoYzHIUXl+qXih/IAxrzzx0XpgPNjf/lMd0OJ/wHDG9ByG8ty3IHM1mOnr/p/aiUC1FN36F8EQIDAQAB"
	Self_private_key          = "MIIEowIBAAKCAQEAiZLlVwXLci8GV2JEJo+e/foAE1gGFdfj6t17dyqEqG26kOFC7/PJIsN5epvnGjopRdq7zhDvEjq/89wulQIWrUiJN1iRNTMNZQg1/TJv5ls62ahBlYIbO7jlW4wPfVO94TNJOLDfpEcLNzR01laQFRHpMSuXFCsoYzHIUXl+qXih/IAxrzzx0XpgPNjf/lMd0OJ/wHDG9ByG8ty3IHM1mOnr/p/aiUC1FN36F8EQIDAQABAoIBAQCHx/cY47w/j1AX8QHIeVn328Y1UXGGBTMG15ev3x/aXIi/4cJ+IdxSaiJIpjst/hEdRfKAe1LvvwxKA/4C9XOa/nGMfEymBF0mELAESWyji27GUgxtwUONmjit7BJUxkatoW2rEsman1e6/ObEgeflV+EwbfNaUmRRuQdxOvwq3HWrCiQeHNdbhXeh7nDHrxi9xLI4XuWHkxTV0rGiar9jnNTLFaKaEzZQK8JcX40VG5MLk8CykZ4G5A+Tjl4ut43IJXGcrNg2EdTpAdVYaUj5WqRs6fc5kgROepMpjFF8iEHlsRdkBR87iIvN1RZ68PW8LheQDGf+HqBvHnrj3/VRAoGBALzhqgbgW9+Bn4CTjs8OgvqWsEOC6HXaCxwXkqfAHetMA5i16WUAVyMubicuUPxG4j43yjqkqOlKaSEbdxy3qves4XJQeIc5sLp1GJus7EusOil8cnWrzBEWVqrKnMPDSVrV+V4pQaD4APLPOPl9/pUT3i9Axf2QjLpXkn/H/2m1AoGBALp11FdW8RMfgOdvwUxxHD9Bm3x5IZv/Z2fd2y4tsSrGmaz2IFLBew15WkTHrDQGxLJS6r5VMqovHWc73d0Hmm6XRt38QNxIAb6MjHsBn7ul1AjpHBZGohUPANvrV6uM2KeZXo1NA70zD5cH7luYWI7bFKFIeEt1O0vtmq21X9JtAoGAYVGIUGizDZL1AsOEdkzM0Z5ojTBa47YHuV6v8ny7LawJwlogOikVvIvEt61WjtVa5qHKMbL7UNBFIIjNM1+y2FAcDNFHeK0R0NBacIOFcGv5v7xeISD2UOuIlhE0+myZVBMhnBF3vh9qJbD9cxcm39rPxNsD6GTdDXnngq0ifW0CgYBk150Dr22qHfulL3enU/Um8OCarRhUOgk+z2ney69ppwct198bYrCeVOdRE3w6lv6CQv3Z+lHwYJLSZjpTc+09qmsVW3voprjqyTCgxfwRjFnkh8487e5y3S5lwh4kFYSHABd27BP9m0PvNsbemsIqYKoDoCIPDVQIeHSTReiQ8QKBgGWFIxVuEhLuIdvwOcT717q6FdHhmebLvPnJ7bjVY5TXCUvVPHOBpo2Xn2wxacSvMipQ+4/eX736MPq2V21WuyQCnSxHzquL0FAtnMGGYj4q8DPbjRMAuMZJqtD77AP63cPY18/glDnekyBuhfjsEGIKjIVuniefrGkz0Ss7NBp1"
	PKCS1            PKCSType = 1
	PKCS8            PKCSType = 2
	RSA                       = "RSA"
	RSA2                      = "RSA2"
	App_id                    = "2021152147896523"
)

type ReceiveBizContent struct {
	AppId            string `xml:"AppId"`
	FromUserId       string `xml:"FromUserId"`
	CreateTime       int64  `xml:"CreateTime"`
	MsgType          string `xml:"MsgType"`
	EventType        string `xml:"EventType"`
	ActionParam      string `xml:"ActionParam"`
	AgreementId      string `xml:"AgreementId"`
	AccountNo        string `xml:"AccountNo"`
	MsgId            string `xml:"MsgId"`
	UserInfo         string `xml:"UserInfo"`
	FromAlipayUserId string `xml:"FromAlipayUserId"`
}

func (a *AliopenController) GateWay() {
	service := a.GetString("service")
	biz_content := a.GetString("biz_content")

	var receivebizcontent ReceiveBizContent
	utf8xml, err := GbkToUtf8([]byte(biz_content))

	if err != nil {
		log.Println("gbk to utf's err is : ", err)
	}
	err = encodingxml.Unmarshal(utf8xml, &receivebizcontent)

	if err != nil {
		log.Println("get ali gateway unxml's err is : ", err)
	}
	alisign := a.GetString("sign")
	if service == "alipay.service.check" && receivebizcontent.EventType == "verifygw" {
		signDate := "biz_content=" + biz_content + "&charset=GBK&service=alipay.service.check&sign_type=RSA2"
		ok, err := alipay.VerifySyncSign(Ali_public_key, signDate, alisign)
		if err != nil {
			log.Println("验签结果 is : ", ok, err)
		}
		pubBody := make(gopay.BodyMap)
		pubBody.Set("biz_content", `<?xml version="1.0" encoding="GBK"?><alipay><response><success>true</success></response></alipay>`)
		waitsignstr := `<success>true</success>` + "<biz_content>" + Self_public_key + "</biz_content>"
		signafter, _ := GetRsaSign(waitsignstr, "RSA2", Self_private_key)
		msg := `<?xml version="1.0" encoding="GBK"?><alipay><response><success>true</success><biz_content>%s</biz_content></response><sign>%s</sign><sign_type>RSA2</sign_type></alipay>`
		waitsendmsg := fmt.Sprintf(msg, Self_public_key, signafter)

		a.Ctx.WriteString(waitsendmsg)

		return
	}
	a.Ctx.WriteString("success")
}

func (a *AliopenController) AliCallBack() {

	a.Data["authinfo"] = "成功"
	a.TplName = "aligrant.tpl"
}

func GbkToUtf8(s []byte) ([]byte, error) {
	reader := transform.NewReader(bytes.NewReader(s), simplifiedchinese.GBK.NewDecoder())
	d, e := ioutil.ReadAll(reader)
	if e != nil {
		return nil, e
	}

	str := string(d)
	str = strings.ReplaceAll(str, `<?xml version="1.0" encoding="gbk"?>`, `<?xml version="1.0" encoding="UTF-8" ?>`)
	str = strings.ReplaceAll(str, `<?xml version="1.0" encoding="GBK" ?>`, `<?xml version="1.0" encoding="UTF-8" ?>`)

	return []byte(str), nil
}
func GetRsaSign(bm string, signType string, privateKey string) (sign string, err error) {
	var (
		block          *pem.Block
		h              hash.Hash
		key            *rsa.PrivateKey
		hashs          crypto.Hash
		encryptedBytes []byte
	)
	pk := FormatPrivateKey(privateKey)

	if block, _ = pem.Decode([]byte(pk)); block == nil {
		return "", errors.New("pem.Decode：privateKey decode error")
	}

	if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		return "", err
	}

	switch signType {
	case RSA:
		h = sha1.New()
		hashs = crypto.SHA1
	case RSA2:
		h = sha256.New()
		hashs = crypto.SHA256
	default:
		h = sha256.New()
		hashs = crypto.SHA256
	}

	if _, err = h.Write([]byte(bm)); err != nil {
		return
	}
	if encryptedBytes, err = rsa.SignPKCS1v15(rand.Reader, key, hashs, h.Sum(nil)); err != nil {
		return
	}
	sign = base64.StdEncoding.EncodeToString(encryptedBytes)
	return
}
func FormatPrivateKey(privateKey string) (pKey string) {
	var buffer strings.Builder
	buffer.WriteString("-----BEGIN RSA PRIVATE KEY-----\n")
	rawLen := 64
	keyLen := len(privateKey)
	raws := keyLen / rawLen
	temp := keyLen % rawLen
	if temp > 0 {
		raws++
	}
	start := 0
	end := start + rawLen
	for i := 0; i < raws; i++ {
		if i == raws-1 {
			buffer.WriteString(privateKey[start:])
		} else {
			buffer.WriteString(privateKey[start:end])
		}
		buffer.WriteByte('\n')
		start += rawLen
		end = start + rawLen
	}
	buffer.WriteString("-----END RSA PRIVATE KEY-----\n")
	pKey = buffer.String()
	return
}
