-- 创建规则命中次数统计表
create table if not exists `cluster_rule_hit` (
    `type` smallint unsigned not null default 0 comment '规则类型',
    `rule_id` varchar(64) not null default '' comment '规则ID',
    `hit` int unsigned not null default 0 comment '命中次数',
    `ext1` int unsigned not null default 0 comment '扩展字段1',
    `ext2` int unsigned not null default 0 comment '扩展字段2',
    `ext3` int unsigned not null default 0 comment '扩展字段3',
    primary key (`type`, `rule_id`)
) charset=utf8mb4;