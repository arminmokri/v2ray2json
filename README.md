# v2ray2json
### Please support my repo with your star.
**v2ray2json** is a Python script for converting 'vmess://', 'vless://', 'trojan://', 'ss://', etc. subscription format to JSON config.
<br/>
The idea and Implementation of this project come from [cuynu/v2rayvn](https://gitlab.com/cuynu/v2rayvn) repository and also [V2rayConfig.kt](https://gitlab.com/cuynu/v2rayvn/-/blob/master/app/src/main/kotlin/com/v2ray/ang/dto/V2rayConfig.kt) file plays a key role.

## Features
- Support vmess:// format.
- Support vless:// format.
- Support trojan:// format.
- Support ss:// format.

## Install and Run the Project
1. You have to make sure to have Python on your computer, for example you can type `python -V` on terminal.
2. For converting subscription to JSON config run `python v2ray2json.py vmess://eyJ2IjoiMiIsInBzIjoiRC1CUk9XTi0xMDI1IiwiYWRkIjoiMTU3LjI0NS40LjE3MCIsInBvcnQiOiI4ODgxIiwiaWQiOiJkYjVhZmFlNC1hYzIzLTQxYTYtODM3OC1mMzA3YTlhNDc0MzYiLCJhaWQiOiIwIiwic2N5IjoiYXV0byIsIm5ldCI6InRjcCIsInR5cGUiOiJodHRwIiwiaG9zdCI6Im1paGFud2ViaG9zdC5jb20iLCJwYXRoIjoiLyIsInRscyI6Im5vbmUiLCJzbmkiOiIiLCJhbHBuIjoiIn0=`
3. As a result, you will see this
```
{
  "_comment": {
    "remark": "D-BROWN-1025"
  },
  "log": {
    "access": "",
    "error": "",
    "loglevel": "error",
    "dnsLog": false
  },
  "inbounds": [
    {
      "tag": "in_proxy",
      "port": 1080,
      "protocol": "socks",
      "listen": "127.0.0.1",
      "settings": {
        "auth": "noauth",
        "udp": true,
        "userLevel": 8
      },
      "sniffing": {
        "enabled": false
      }
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vmess",
      "settings": {
        "vnext": [
          {
            "address": "157.245.4.170",
            "port": 8881,
            "users": [
              {
                "id": "db5afae4-ac23-41a6-8378-f307a9a47436",
                "alterId": 0,
                "security": "auto",
                "level": 8,
                "encryption": "",
                "flow": ""
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "none",
        "tcpSetting": {
          "header": {
            "type": "http",
            "request": {
              "path": [
                "/"
              ],
              "headers": {
                "Host": [
                  "mihanwebhost.com"
                ]
              }
            }
          }
        }
      },
      "mux": {
        "enabled": false,
        "concurrency": 8
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIp"
      }
    },
    {
      "tag": "blackhole",
      "protocol": "blackhole",
      "settings": {}
    }
  ],
  "dns": {
    "servers": [
      "8.8.8.8"
    ]
  },
  "routing": {
    "domainStrategy": "UseIp",
    "rules": [],
    "balancers": []
  }
}
```
