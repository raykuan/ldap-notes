#### RayKuan @ 2017-09-03 10:25:29

# msldap
概述：使用python的pyldap模块操作Microsoft Active Directory

在adhandler.py文件中封装以下功能：  

1、获取域用户信息  

2、获取域密码策略  

3、修改及重置域用户密码  

其他功能可以在此基础上做扩展  

依赖python第三方库：pyldap  

需要AD server颁发证书才能通过ldaps协议636端口修改域用户信息

AD server证书颁发步骤：  

① AD上需要安装证书服务  

② 连接AD的主机上使用http://ad-server-ip/certsrv/打开浏览器申请证书   

③ 如果连接AD的主机是Linux，需要安装openssl包，制作CA证书  


## 更新
2018-02-13 去掉django配置，修改优化adhandler.py文件

## 参考
原文件为handler.py(注：原文出处已不得知，如有侵权请告知删除)，对此文件做了汉化和修改

## 版权
本项目采用GNU协议。如果你更改了此项目的代码用于自己的项目，请开源你更改的代码
