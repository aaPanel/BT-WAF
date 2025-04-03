-- 创建证书信息表
create table if not exists `ssl_info` (
   `id` int unsigned primary key auto_increment,
   `site_id` varchar(255) not null default '' comment '网站id',
   `ssl_name` varchar(255) not null default '' comment '节点状态 0-未授权 1-启用 2-禁用',
   `ssl_type` varchar(255) not null default '' comment '证书类型 0-商用证书 1-let‘s Encrypt 2-测试证书',
   `ssl_path` varchar(255) not null default '' comment '证书所在根路径',
   `domains` text not null comment '申请的域名',
   `apply_type` varchar(255) not null default '' comment '申请的方式  http dns',
   `create_time` int unsigned not null default 0 comment '添加时间',
   index `idx_sid` (`site_id`),
   index `idx_sslType` (`ssl_type`),
   index `idx_sslName` (`ssl_name`)
) charset=utf8mb4;
