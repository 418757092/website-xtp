环境变量设置
  | 变量名        | 是否必须 | 默认值 | 备注 |
  | ------------ | ------ | ------ | ------ |
  | DOMAIN       | 否 |      |项目分配的域名，用于自动访问保活|
  | AUTO_ACCESS  | 否 |  false |false关闭自动访问保活，true开启，需同时填写PROJECT_URL变量|
  | PORT         | 否 |  3000  |http服务监听端口     |
  | KEY          | 是 | 161fc0b2-cfa3-4053-8d51-20aeee66c2dd|用户的唯一标识符(UUID),使用悟空v1在不同的平台部署需要修改|
  | WUKONG_SERVER| 是 |        | 悟空面板域名，v1：nz.aaa.com:8008  v0: nz.aaa.com  |
  | WUKONG_PORT  | 否 |        | 悟空v1没有此项，悟空v0端口为{443,8443,2096,2087,2083,2053}其中之一时，开启tls|
  | WUKONG_KEY   | 是 |        | 悟空v1 或v0 密钥                 |
  | NAME         | 否 |  Vl   | 节点名称前缀，例如：Koyeb Fly        |
  | SUB_PATH     | 否 |  sub   | 节点订阅路径                       |
