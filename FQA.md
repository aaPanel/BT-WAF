
#  **常见问题**

## **问：无法登录堡塔云WAF管理界面，如何排查？**
答：
>  注意需要ROOT权限执行命令
1. 检查管理程序是否运行? 查看管理程序状态：`btw admin_status`
        如果没有启动，请尝试手动启动管理程序：`btw 2`    
2. 检查是否使用完整的访问地址进行访问？查看访问地址命令：`btw 6`
3. 检查系统防火墙是否开放访问端口?
4. 服务器提供商的安全组是否开放访问端口?

<br/>

## **问：部署堡塔云WAF后，回源服务器的网站日志全部记录为堡塔云WAF服务器的IP,如何显示真实的客户IP ？**
答：在回源服务器的网站配置中添加以下配置: 
### nginx:
```
    set_real_ip_from 0.0.0.0/0 ;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
```
<br/>

## **问：堡塔云WAF添加了网站，使用浏览器访问域名提示404**
答：
1. 检查是否使用正确的访问方式？请注意区分 **`https`**  与 http
2. 检查回源服务器（源站地址）是否有相关域名的网站？
3. 检查在堡塔云WAF的网站域名是否正确？
<br/>

## **问：堡塔云WAF添加了网站，使用浏览器访问域名提示502**
答：
1. 请检查源站地址配置是否正确？如果回源服务器没有开启SSL，使用 **`https`** 访问回源服务器将显示502错误
2. 请检查堡塔云WAF是否可以连接回源服务器（源站地址）尝试使用在堡塔云WAF服务器上执行命令检查是否可以连接：
	> 请注意修改：“防护域名” 修改成网站域名，“源站地址” 修改成回源服务器的IP

```
curl -H "Host: 防护域名" http://源站地址
 ```
<br/>

## **问：浏览器提示重定向次数过多  ERR_TOO_MANY_REDIRECTS**
答：

1. 请检查回源服务器的网站是否设置强制HTTP，如果有尝试关闭，浏览器使用无痕模式再访问是否正常？
2. 请检查回源服务器的网站配置是否存在错误的URL配置，其中一个URL重定向到另一个URL，而后者又重定向回前者，导致循环重定向。
3. 网站的重定向（伪静态）设置可能存在问题，导致无限循环重定向。

可以参考此教程进行排查: [301重定向的次数过多](https://www.kancloud.cn/kern123/cloudwaf/3205938)

<br/>

## **问：堡塔云WAF是否可以与网站服务器部署在同一台服务器上**
答：
不建议这样部署，这样单服务器的负载会更高、服务器宕机概率增大。非纯净的环境会提高安装失败率。
如果能接受这些风险，堡塔云WAF也可以直接部署在网站服务器上。您需要：
将原本监听 80 或 443 端口的网站服务改到其他端口，让堡塔云WAF监听 80 或 443 端口

<br/>

## **问：感觉增加了堡塔云WAF 后网站变慢了，如何排查？**
答：
1.  先确认堡塔云WAF服务器与回源服务器负载是否正常？可以使用top命令检查
2. 在堡塔云WAF服务器执行命令，检查堡塔云WAF服务器与回源服务器的网络：
    > 请注意修改：“防护域名” 修改成网站域名，“源站地址” 修改成回源服务器的IP

```

Site="防护域名"
Source="源站地址"

curl -H "Host: ${Site} " -v -o /dev/null -s -w ' 总请求时间: %{time_total}\n HTTP响应状态码: %{http_code}\n DNS解析时间: %{time_namelookup}\n 连接所花费的时间: %{time_connect}\n 从请求开始到接收到第一个字节之间的时间: %{time_starttransfer}\n 建立SSL/TLS连接所花费的时间: %{time_appconnect}\n' http://${Source}

```
* 如果 DNS解析时间 过大，请检查 DNS server 配置，可以尝试更换DNS
* 如果 连接所花费的时间 过大，请检查堡塔云WAF与回源服务器之间的网络状态
* 如果 从请求开始到接收到第一个字节之间的时间 过大，请检查回源服务器状态，是否出现系统负载过高

<br/>

## **问：网站一会可以访问，一会访问出错，如何排查？**
答：
1. 请检查网站服务器是否有使用waf，如果有，尝试将云WAF服务器的IP添加到白名单中或者开启CDN，再测试是否正常？
2. 检查云WAF到网站服务器的网络是否稳定？

<br/>

## **问：发送域名如何设置？云WAF添加的网站域名与网站服务器的域名不一致如何设置**

答：一般不只需要默认设置即可，如果云WAF添加的网站域名与网站服务器的域名不一致时使用     如：
-  云WAF上的域名是： user.admin.com
- 网站服务器的域名是： admin.admin.com
- 那么 **发送域名** 设置为： admin.admin.com

<br/>

## **问：如何查看堡塔云WAF管理界面的访问链接**
答：使用SSH工具执行命令： `btw 6`  可以查看访问链接

**访问地址说明：**
如：https://192.168.66.173:8379/a01907f7
- 协议：https
- IP地址：192.168.66.173
- 端口：8379
- 安全入口：/a01907f7  
- **://** 是分隔 协议 和 IP地址 的标记
- **:** 是分隔 IP地址 和 端口 的标记
<br/>

## **问：是否有类似bt 命令行工具**
答：有的，可以使用 `btw` 打开命令行工具

<br/>

## **问：如何卸载云WAF？**

答：卸载命令如下
```
URL=https://download.bt.cn/cloudwaf/scripts/install_cloudwaf.sh && if [ -f /usr/bin/curl ];then curl -sSO "$URL" ;else wget -O install_cloudwaf.sh "$URL";fi;bash install_cloudwaf.sh uninstall
```

<br/>
