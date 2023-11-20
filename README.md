<div align="center">
<img src="https://www.bt.cn/static/new/images/logo.svg" alt="Btwaf " width="300"/>
</div>

<h1 align="center">堡塔云WAF</h1>

<div align="center">

[![BTWAF](https://img.shields.io/badge/btwaf-BTWAF-blue)](https://github.com/aaPanel/BT-WAF)
[![openresty](https://img.shields.io/badge/openresty-luajit-blue)](https://github.com/aaPanel/BT-WAF)
[![version](https://img.shields.io/github/v/release/aaPanel/BT-WAF.svg?color=blue)](https://github.com/aaPanel/BT-WAF)
[![social](https://img.shields.io/github/stars/aaPanel/BT-WAF?style=social)](https://github.com/aaPanel/BT-WAF)

</div>
<p align="center">
  <a href="https://www.bt.cn/new/btwaf.html">官网</a> | 
  <a href="https://www.kancloud.cn/kern123/cloudwaf/3198565">使用教程</a> |
  <a href="https://btwaf-demo.bt.cn:8379/c0edce7a">演示站(Demo)</a> |
  <a href="https://yenvb8apub.feishu.cn/sheets/AQafs3FTEhYw8VtEXPJccZwdnUh">ARM和国产系统兼容表</a>
</p>


## 堡塔云WAF介绍

>**免费的私有云WAF防火墙**
堡塔云WAF经过千万级用户认证、为您的业务保驾护航
采用反向代理的方式,网站流量先抵达堡塔云WAF
经过堡塔云WAF检测和过滤后，再转给原来提供服务的网站服务器。
堡塔云WAF是一个开源的Web应用程序防火墙，它可以保护网站免受SQL注入，XSS，CSRF，SSRF，命令注入，代码注入，本地文件包含，远程文件包含等攻击
**兼容ARM和国产系统**



## 在线演示(Demo)
演示地址：https://btwaf-demo.bt.cn:8379/c0edce7a<br/>

## 堡塔云WAF工作原理图
<p align="center">
    <img src="./img/btwaf.png">
</p>




## 在线安装
使用SSH工具登录服务器，执行以下命令安装：
```shell
URL=https://download.bt.cn/cloudwaf/scripts/install_cloudwaf.sh && if [ -f /usr/bin/curl ];then curl -sSO "$URL" ;else wget -O install_cloudwaf.sh "$URL";fi;bash install_cloudwaf.sh
```
<p align="center">
    <img src="./img/install.png">
</p>

## **离线安装**
> 注意，此安装方式适用于服务器无法连接公网节点时的选择
* 离线安装时必须手动安装 docker，否则无法安装
* 离线安装前请确保您的服务器存在 tar gzip curl netstat ss docker 命令，可以使用此命令检查是否存在：
```
Packs=("curl" "tar" "gzip" "netstat" "ss" "docker" ); for pack in "${Packs[@]}"; do command -v "$pack" >/dev/null 2>&1 || echo -e "\033[31mError: $pack 命令不存在\033[0m"; done
```

- 离线安装脚本：[点击下载离线安装脚本](https://download.bt.cn/cloudwaf/scripts/install_cloudwaf.sh)
- 下载镜像文件：[点击下载镜像文件](https://download.bt.cn/cloudwaf/package/btwaf_mysql_openresty-latest.tar.gz)
- 下载cloudwaf程序文件：[点击下载cloudwaf程序文件](https://download.bt.cn/cloudwaf/package/cloudwaf-latest.tar.gz)

将上面的文件下载后，使用Xftp、winscp等工具上传到服务器中，将下载的文件放在相同的路径，然后执行安装命令离线安装：
```
bash install_cloudwaf.sh offline
```
<p align="center">
    <img src="./img/lixian.png">
</p>

> 安装完成后，登录步骤与在线相同


## 功能介绍
1.首页概览
<p align="center">
    <img width="1941" alt="image" src="https://github.com/aaPanel/BT-WAF/assets/31841517/19762b6c-bd79-4bda-bd99-ea1af54c17c2">
</p>

2.拦截记录
<p align="center">
    <img width="1986" alt="image" src="https://github.com/aaPanel/BT-WAF/assets/31841517/bf1b113e-143d-4e58-8bf2-a75d21f54f64">
</p>

##  联系我们
>1. GitHub Issue 
>2. WX 二维码
<img width="239" alt="image" src="https://bt-1251050919.cos.ap-guangzhou.myqcloud.com/btwafGroup.png?a=1">
