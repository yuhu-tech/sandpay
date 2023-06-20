# sandpay

[![golang](https://img.shields.io/badge/Language-Go-green.svg?style=flat)](https://golang.org) [![GitHub release](https://img.shields.io/github/release/shenghui0779/sandpay.svg)](https://github.com/shenghui0779/sandpay/releases/latest) [![pkg.go.dev](https://img.shields.io/badge/dev-reference-007d9c?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/shenghui0779/sandpay) [![Apache 2.0 license](http://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](http://opensource.org/licenses/apache2.0)

杉德支付 Go SDK

```sh
go get -u github.com/shenghui0779/sandpay
```

## 目录分级
由于蕴章账户侧和受理侧使用的验签公钥不同，且接口规范不同，因此将其拆分为两个不同子目录
- account: 云账户(账户侧)
- acceptance: 云账户(受理侧)

> 账户侧 和 受理侧 使用的验签公钥不一样, 账户侧使用`sand-pro.cer`, 受理侧使用`sand.cer`

## 证书的公私钥的各种转换
```shell script
  openssl pkcs12 -in xxxx.pfx -nodes -out server.pem  #将pfx格式的证书生成为原生格式pem私钥
  openssl rsa -in server.pem -out server.key          #生成为rsa格式私钥文件
  openssl x509 -in server.pem  -out server.crt
  openssl pkcs12 -in xxxx.pfx -clcerts -nokeys -out key.cert
  openssl x509 -inform der -in certificate.cer -out certificate.pem # der格式的.cer公钥证书转为pem格式
  openssl x509 -in test.cer -out test.pem
```

