# sandpay

[![golang](https://img.shields.io/badge/Language-Go-green.svg?style=flat)](https://golang.org) [![GitHub release](https://img.shields.io/github/release/shenghui0779/sandpay.svg)](https://github.com/shenghui0779/sandpay/releases/latest) [![pkg.go.dev](https://img.shields.io/badge/dev-reference-007d9c?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/shenghui0779/sandpay) [![Apache 2.0 license](http://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](http://opensource.org/licenses/apache2.0)

杉德支付 Go SDK

```sh
go get -u github.com/shenghui0779/sandpay
```

## 目录分级
- account: 云账户账户侧
- acceptance: 云账户受理侧

## 解析pem证书的公钥和私钥
```shell script
  openssl pkcs12 -in xxxx.pfx -nodes -out server.pem  #生成为原生格式pem 私钥
  openssl rsa -in server.pem -out server.key          #生成为rsa格式私钥文件
  openssl x509 -in server.pem  -out server.crt
  openssl pkcs12 -in xxxx.pfx -clcerts -nokeys -out key.cert
  openssl x509 -inform der -in certificate.cer -out certificate.pem # der格式的.cer公钥证书转为pem格式
```

