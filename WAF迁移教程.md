
#  如何将云WAF迁移到新的服务器?


> **迁移会影响网站的访问，建议在用户访问少时操作**
> 堡塔云WAF版本最好是一致的
> 注意：检查执行的每一步是否有错误？

# 一、环境介绍
## **旧**的云WAF服务器环境:
* 操作系统：Ubuntu 20.04
* 网站域名：nw1.kern123.tk
* 服务器IP：192.168.66.156
* 登录地址：https://192.168.66.156:8379/5f0eb9aa
* 云WAF帐号与密码：5c32ce9b

*****
<br/>

## **新**的服务器环境:
* 操作系统：Debian 11
* 服务器IP：192.168.66.162

*****
<br/>
<br/>

# 二、**旧**的云WAF服务器需要做的步骤
> 首先在旧的服务器进行停止云WAF与备份

使用SSH工具登录旧的服务器，执行以下命令安装：
* 注意需要ROOT权限执行命令
<br/>

## 1. 停止WAF:
```
btw stop
```


<br/>

## 2. 直接打包整个目录进行备份迁移
```
cd /www/ && tar -zcvf cloud_waf.tar.gz cloud_waf
```

![image](https://github.com/aaPanel/BT-WAF/assets/31841517/42273451-e890-493e-ada4-62591808ef70)

<br/>

备份成功后查看文件与验证md5值：
```
ls -ahl 
md5sum cloud_waf.tar.gz
```
![image](https://github.com/aaPanel/BT-WAF/assets/31841517/9882cce6-29b9-4aea-a591-5868ad1ce12a)

<br/>

## 3.下载备份文件 cloud_waf.tar.gz

- 可以使用 Xftp、Winscp 等工具下载到本地电脑中，然后再上传到新的服务器到 `/root` 目录
> **注意检查下载的文件是否完整**

<br/>

- 或者使用scp 命令直接远程复制到新的服务器：
> 注意：将 “新的服务器IP” 更换成您的新服务器IP
> 第一次连接需要输入yes, 然后再输入新服务器的 root 密码

```
scp cloud_waf.tar.gz root@新的服务器IP:/root/
```

![image](https://github.com/aaPanel/BT-WAF/assets/31841517/53edcc08-e7d2-49ac-b034-8d9f71d6c31a)

<br/>
<br/>


# 三、**新**的服务器需要做的步骤：
## 1.上传并且解压还原mysql文件

使用SSH工具登录 **新**的服务器，执行以下命令安装：
* 注意需要ROOT权限执行命令


1. 在**新**的服务器上确认备份文件是否存在？确认md5值是否一致？
    ```
    cd /root/ && ls -lh && md5sum cloud_waf.tar.gz
    ```
![image](https://github.com/aaPanel/BT-WAF/assets/31841517/fb7a05b4-1f30-4611-8185-7331bb635bad)

<br/>

2. 解压备份文件
    ```
    tar -zxf cloud_waf.tar.gz
    ```

<br/>

3. 建立目录与恢复mysql数据
    ```
    mkdir -pv /www/cloud_waf/nginx/conf.d/waf/

    \cp -arpf /root/cloud_waf/nginx/conf.d/waf/mysql_default.pl /www/cloud_waf/nginx/conf.d/waf/mysql_default.pl

    mv /root/cloud_waf/mysql /www/cloud_waf/mysql
    ```

<br/>

4. 查看文件是否成功移动
    ```
    ls /www/cloud_waf/mysql/
    ```

![image](https://github.com/aaPanel/BT-WAF/assets/31841517/24e40245-0bd6-4644-bfd9-c378a771ace1)

<br/>
<br/>

## 2. 在**新**的服务器中安装云WAF
1. **新**的服务器执行命令安装云WAF
    ```
    URL=https://download.bt.cn/cloudwaf/scripts/install_cloudwaf.sh && if [ -f /usr/bin/curl ];then curl -sSO "$URL" ;else wget -O install_cloudwaf.sh "$URL";fi;bash install_cloudwaf.sh
    ```
![image](https://github.com/aaPanel/BT-WAF/assets/31841517/bc1b2a6c-aece-4b79-9d02-5b624bbf5c83)
    > 注意：这里请忽略显示的登录信息，因为下面会将旧的云WAF数据恢复到新的服务器中。
    
<br/>

2. 安装成功后，等待5秒，停止云WAF
    ```
    sleep 5 && btw stop
    ```
<br/>

3. 等待5秒后，恢复旧云WAF的数据
    ```
    sleep 5 && \cp -arpf /root/cloud_waf/* /www/cloud_waf
    ```
    > **注意：查看是否有错误**

<br/>

4. 查看文件是否成功复制
    ```
    ls -l /www/cloud_waf
    ```

<br/>

5. 启动云WAF
    ```
    btw start
    ```
    > 注意: **检查是否启动成功**

![image](https://github.com/aaPanel/BT-WAF/assets/31841517/424dac63-5794-4dc8-991c-85e53a0bc696)

<br/>

## 3.登录新的云WAF
查看云WAF登录地址信息，可以查看到仅更换了IP，其他信息没有改变。
```
btw 6
```

![image](https://github.com/aaPanel/BT-WAF/assets/31841517/2be4e0ec-4ae7-4a74-a13c-76600629e23d)
<br/>

使用显示的登录地址来登录云WAF
如：https://192.168.66.162:8379/5f0eb9aa

> 注意：请使用旧的云WAF帐号与密码进行登录，如果忘记了可以使用 `btw 10` 命令重置密码

<br/>
<br/>

## 4.检查云WAF功能是否正常？
如何检查：可以检查旧的云WAF有数据的界面，比如

- 首页概览
- 拦截日志
- 操作日志
- 网站列表

拦截日志：
![image](https://github.com/aaPanel/BT-WAF/assets/31841517/d201a619-272d-46e8-aab4-42f8b3933f89)

<br/>

如果不正常将**无数据显示** 或者 **请求出错，请稍后再试**
在**新**的云WAF中执行`btw 18`命令检查是什么原因导致的

<br/>

**正常请继续下一步**


<br/>
<br/>

## 5.检查网站是否正常?
首先将域名的A记录解析的IP 更换为 新服务器的IP
- 即将 旧的云WAF服务器IP: 192.168.66.156 更换为新的云WAF服务器IP: 192.168.66.162
- 等待解析生效后测试访问您的域名，如: http://nw1.kern123.tk


<br/>

通过以下方式查看新的云WAF服务器是否有生效:
- 首页概览 --> 今日请求数
- 网站列表 --> 今日访问/拦截
- 网站列表 相关域名 的日志是否有内容

> 如果没有记录，建议检查更换的域名A记录解析是否生效？解析记录是否正确？


<br/>

**网站是否正常需要您自行检查，可以随意点击几个功能来测试是否正常**


<br/>

**如果没有问题，这么迁移就完成了。**
确认没有问题后，您可以选择删除解压出来的文件了，同时建议保留备份压缩文件。
`rm -rf /root/cloud_waf`

<br/>
<br/>


# **教程总结**

- **旧**的云WAF服务器：
1.停止云WAF
2.备份云WAF
3.下载备份文件

<br/>

- **新**的云WAF服务器
1.上传备份文件
2.解压备份文件
3.建立相关目录
4.恢复mysql数据
5.安装云WAF
6.停止云WAF
7.恢复云WAF
8.检查云WAF是否正常
9.更换域名A记录解析
10.检查网站是否正常

<br/>
<br/>

# **如果是同一台服务器，需要重新安装操作系统如何备份恢复？**
> **不需要**：更换域名A记录解析 
> 基本上与迁移到新的服务器相同

- 在云WAF服务器操作流程：
    1. 停止云WAF
    2. 备份云WAF
    3. 下载备份文件
    4. 重新安装操作系统
    5. 上传备份文件
    6. 解压备份文件
    7. 建立相关目录
    8. 恢复mysql数据
    9. 安装云WAF
    10. 停止云WAF
    11. 恢复云WAF
    12. 检查云WAF是否正常
    13. 检查网站是否正常


<br/>
<br/>

如使用中有问题，请联系我们：
**加入微信讨论群**
<br/>
<br/>
<img width="239" alt="image" src="https://bt-1251050919.cos.ap-guangzhou.myqcloud.com/btwafGroup.png">
