### 一、概述

LDAP：Lightweight Directory Access Protocol  轻量级目录访问协议  

LDAP协议基于X.500标准, 与X.500不同，LDAP支持TCP/IP, 是跨平台的和标准的协议 

### 二、基本概念

在LDAP中信息以树状方式组织，在树状信息中的基本数据单元是条目，而每个条目由属性构成，属性中存储有属性值

                         O(zhangyang.com)

                    /       /

                 ou1     ou2

                /    /  

             test
 

(1)O:Organization 组织  

根的表示方法（参考LDAP Server）  

a. 组织名称(x.500)  

假设组织名称为zhangyang则o=zhangyang  


b. 域名  

假设组织域名为zhangyang.com则o=zhangyang.com或dc=zhangyang, dc=com  


(2)OU: Organization Unit 组织单元  

(3)Entry: 条目,记录， 由DN唯一标识  

(4)DN: Distinguished Name，每个叶子结点到根的路径就是DN, 如: cn=test, ou=ou1, o=zhangyang.com  

(5)RDN: Relative Distinguished Name，叶子结点本身的名字是RDN, 如:test就是RDN  

(6)Base DN: 基准DN，指定LDAP search的起始DN, 即从哪个DN下开始搜索  

如搜索组织单元为ou1，则base DN为ou=ou1,o=O 或 ou=ou1,dc=zhangyang, dc=com  

(7)AttributeType：属性类型，      

(8)ObjectClass: 对象类,由多个attributetype(属性类型)组成, 每个条目(Entry)必须属于某个或多个对象类（Object Class）  

(9)schema文件: 定义对象类、属性类型、语法和匹配规则, 有系统schema，用户也可自定义schema文件  

(10) LDIF:LDAP Interchange Format, 是指存储LDAP配置信息及目录内容的标准文本文件格式。LDIF文件常用来向目录导入或更改记录信息，  


基本格式：AttributeName: value  

属性名 冒号 空格 属性值  

如  

dn: dc=zy,dc=net  

objectclass: dcObject  

objectclass: organization  

dc: zy  

o: zhangyang  


(11)监听端口  

TCP/IP port: 389  

SSL port: 636 

### 三、Search filter:

每个表达式都放在括号内，多个表达式用与(&)，或(|)，非(!)等连结  

&(&(filter1)(filter2)...(filtern))   filter1,filter2,...,filtern  同时满足  

|(|(filter1)(filter2)...(filtern))   filter1,filter2,...,filtern  至少有一个满足  

!(!(filter)) 非filter  


filter支持通配符(wildcard)*  

*表示零或多个字符  

如（objectclass=*）,指列出所有类型的记录（不过分类） 

### 四、LDAP客户端和LDAP服务器端交互过程

1. 绑定。LDAP客户端与LDAP服务器建立连接。可匿名绑定，也可以用户名+密码形式绑定(具体参考LDAP Server, AD不支持匿名查询)。  

2. LDAP客户端向LDAP服务器发出查询、添加、修改、删除entry等操作。    

3.解除绑定。LDAP客户端与LDAP服务器断开连接。

### 五、LDAP软件

常见的LDAP服务器：Microsoft Active Directory, IBM Domino, openldap
常见的LDAP客户端： JXplorer
