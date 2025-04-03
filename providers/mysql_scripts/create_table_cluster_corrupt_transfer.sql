-- 创建网站故障转移相关表
-- @author Zhj<2023-12-21>

-- 故障转移辅助表
create table if not exists `cluster_corrupt_transfer_help` (
    `group_id` int unsigned not null default 0 comment '负载均衡组ID （主键）',
    `node_id` int unsigned not null default 0 comment '节点ID（主键）',
    `cnt` int unsigned not null default 0 comment '连续故障次数',
    `is_corrupted` tinyint unsigned not null default 0 comment '该节点是否故障',
    `last_time` int unsigned not null default 0 comment '上一次检测时间',
    primary key (`group_id`, `node_id`)
) charset=utf8mb4;