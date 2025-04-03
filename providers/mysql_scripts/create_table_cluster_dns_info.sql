-- 创建dns接管表
create table if not exists `dns_info` (
    `id` int unsigned primary key auto_increment,
    `dns_name` varchar(255) not null default 0 comment 'dns厂商名称',
    `status` int not null default 0 comment '接管状态 0-未接管 1-接管中',
    `api_key` text not null comment 'api密钥',
    `domains` text not null comment '接管的域名',
    `ps` text not null comment '备注',
    `create_time` int unsigned not null default 0 comment '添加时间',
    index `idx_dnsNameInfo` (`dns_name`)
) charset=utf8mb4;
