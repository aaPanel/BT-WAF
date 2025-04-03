-- 创建数据同步时间记录表
create table if not exists `cluster_sync_time` (
    `node_id` int unsigned not null default 0 comment '节点ID（主键）',
    `type` smallint unsigned not null default 0 comment '数据同步类型（主键）',
    `last_sync_time` int unsigned not null default 0 comment '上一次同步时间',
    `max_time` int unsigned not null default 0 comment '上一次获取到的数据中的最大时间',
    primary key (`node_id`, `type`)
) charset=utf8mb4;