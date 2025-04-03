-- 创建网站检测表
create table if not exists `site_check` (
    `id` int unsigned primary key auto_increment,
    `site_id` varchar(64) not null default '' comment '网站id',
    `domain_string` varchar(255) not null default '' comment '网站域名',
    `port` varchar(6) not null default '' comment '网站端口',
    `create_time` int unsigned not null default 0 comment '添加时间',
    index `idx_checkSiteId` (`site_id`),
    index `idx_domainString` (`domain_string`),
    index `idx_port` (`port`)
) charset=utf8mb4;
