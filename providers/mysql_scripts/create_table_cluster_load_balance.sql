-- 创建负载均衡组表
create table if not exists `load_balance` (
    `id` int unsigned primary key auto_increment comment '负载均衡分组ID',
    `corrupt_check` tinyint unsigned not null default 0 comment '故障检测启用状态 0-未启用 1-启用',
    `load_name` char(64) not null default '' comment '负载均衡分组名称',
    `dns_name` text not null comment 'dns厂商名称',
    `load_method` char(32) not null default '' comment '负载均衡方式 region-地区 weight-权重 dns-dns轮询',
    `nodes` text not null comment '负载均衡分组节点配置详情',
    `ps` text not null comment '备注',
    `create_time` int unsigned not null default 0 comment '添加时间',
    index `idx_LoadDnsName` (`load_name`),
    index `idx_corruptCheck` (`corrupt_check`)
) charset=utf8mb4;
