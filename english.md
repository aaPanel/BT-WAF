<div align="center">
<img src="https://www.aapanel.com/static/images/aaPanel.png" alt="aaWAF " width="300"/>
</div>

<h1 align="center">aaWAF</h1>

<div align="center">

[![aaWAF](https://img.shields.io/badge/btwaf-BTWAF-blue)](https://github.com/aaPanel/BT-WAF)
[![openresty](https://img.shields.io/badge/openresty-luajit-blue)](https://github.com/aaPanel/BT-WAF)
[![version](https://img.shields.io/github/v/release/aaPanel/BT-WAF.svg?color=blue)](https://github.com/aaPanel/BT-WAF)
[![social](https://img.shields.io/github/stars/aaPanel/BT-WAF?style=social)](https://github.com/aaPanel/BT-WAF)

</div>
<p align="center">
  <a href="https://www.aapanel.com/new/waf.html">official website</a> | 
  <a href="https://www.kancloud.cn/kern123/cloudwaf/3198565">Using Tutorials</a> |
  <a href="https://btwaf-demo.bt.cn:8379/c0edce7a">Demo</a> |
  <a href="https://yenvb8apub.feishu.cn/sheets/AQafs3FTEhYw8VtEXPJccZwdnUh">ARM and Domestic System Compatibility Table</a> |
<a href="./english_update.md">Update log</a>
</p>


## aaWAF Introduction

>**Free private cloud WAF firewall**
Baota Cloud WAF has been certified by millions of users to safeguard your business
By using reverse proxy, website traffic first reaches the Baota Cloud WAF
After being detected and filtered by Baota Cloud WAF, it will be transferred to the website server that originally provided the service.
Baota Cloud WAF is an open-source web application firewall that can protect websites from SQL injection, XSS，CSRF，SSRF， Command injection, code injection, local file inclusion, remote file inclusion, and other attacks



## Demo
URL：https://btwaf-demo.bt.cn:8379/c0edce7a<br/>

## Working principle diagram of Baota Cloud WAF
<p align="center">
    <img src="./img/btwaf.png">
</p>




## install
Use SSH tool to log in to the server and execute the following command to install:
```shell
URL=https://node.aapanel.com/cloudwaf_en/scripts/install_cloudwaf_en.sh && if [ -f /usr/bin/curl ];then curl -sSO "$URL" ;else wget -O install_cloudwaf_en.sh "$URL";fi;bash install_cloudwaf_en.sh
```
<p align="center">
    <img src="./img/install.png">
</p>

## **Offline installation**
> Note that this installation method is suitable for selecting when the server cannot connect to a public network node
* Docker must be manually installed during offline installation, otherwise it cannot be installed
* Before offline installation, please ensure that your server has the tar gzip curl netstat ss docker command. You can use this command to check if it exists:
```
Packs=("curl" "tar" "gzip" "netstat" "ss" "docker" ); for pack in "${Packs[@]}"; do command -v "$pack" >/dev/null 2>&1 || echo -e "\033[31mError: $pack cmd not found\033[0m"; done
```

- Offline installation script:[Click to download offline installation script](https://node.aapanel.com/cloudwaf_en/scripts/install_cloudwaf_en.sh)
- Download image file:[Download image file](https://node.aapanel.com/cloudwaf_en/package/btwaf_mysql_openresty-latest.tar.gz)
- Download the cloudwaf program file:[Download cloudwaf](https://node.aapanel.com/cloudwaf_en/package/cloudwaf-latest.tar.gz)

After downloading the above files, use tools such as Xftp and winscp to upload them to the server, place the downloaded files in the same path, and then execute the installation command to install offline:
```
bash install_cloudwaf.sh offline
```
<p align="center">
    <img src="./img/lixian.png">
</p>

> After installation, the login steps are the same as online


## Function Introduction
0.3D map
<p align="center">
    <img width="1941" alt="image" src="./img/222.gif">
</p>
1.Home Overview
<p align="center">
    <img width="1941" alt="image" src="https://github.com/aaPanel/BT-WAF/assets/31841517/19762b6c-bd79-4bda-bd99-ea1af54c17c2">
</p>

2.Intercept record
<p align="center">
    <img width="1986" alt="image" src="https://github.com/aaPanel/BT-WAF/assets/31841517/bf1b113e-143d-4e58-8bf2-a75d21f54f64">
</p>

3.Hit record
<p align="center">
    <img width="1986" alt="image" src="./img/rule_git.png">
</p>

4.Attack map
<p align="center">
    <img width="1986" alt="image" src="./img/wafMap.png">
</p>

##  Contact Us
>1. GitHub Issue 
>2. WeChat 
<img width="239" alt="image" src="https://bt-1251050919.cos.ap-guangzhou.myqcloud.com/btwafGroup.png?a=5">
