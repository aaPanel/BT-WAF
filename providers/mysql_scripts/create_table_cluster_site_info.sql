-- 创建网站配置表
create table if not exists `site_info` (
    `id` int unsigned primary key auto_increment,
    `site_id` varchar(255) not null default '' comment '网站id',
    `site_name` varchar(255) not null default '' comment '节点状态 0-未授权 1-启用 2-禁用',
    `server` text not null comment '网站server详细配置',
    `is_cdn` int unsigned not null default 0 comment '是否启用cdn 0-未启用 1-启用',
    `load_group_id` int unsigned not null default 0 comment '负载均衡分组id',
    `status` int unsigned not null default 1 comment '网站状态 0-暂停 1-运行中',
    `create_time` int unsigned not null default 0 comment '添加时间',
    `update_time` int unsigned not null default 0 comment '更新时间',
    index `idx_sid` (`site_id`),
    index `idx_loadSid` (`load_group_id`)
) charset=utf8mb4;
