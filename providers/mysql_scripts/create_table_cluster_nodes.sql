-- 创建节点表
create table if not exists `cluster_nodes` (
    `id` int unsigned primary key auto_increment,
    `group_id` int unsigned not null default 0 comment '负载均衡分组ID 0-未分组 1-默认分组',
    `status` tinyint unsigned not null default 0 comment '节点状态 0-未授权 1-启用 2-禁用',
    `is_online` tinyint unsigned not null default 0 comment '节点在线状态 0-离线 1-在线',
    `type` tinyint unsigned not null default 1 comment '节点类型 1-常驻节点 2-临时节点',
    `create_time` int unsigned not null default 0 comment '添加时间',
    `release_time` int unsigned not null default 0 comment '临时节点自动释放时间 Unix时间戳 0-表示手动释放',
    `itself` tinyint unsigned not null default 0 comment '是否主控自身',
    `sid` char(32) not null default '' comment '节点ID',
    `last_heartbeat_time` int unsigned not null default 0 comment '上一次心跳时间',
    `remark` varchar(64) not null default '' comment '节点备注',
    `detail` json comment '节点配置详情',
    unique index `idx_sid` (`sid`),
    index `idx_groupId` (`group_id`)
) charset=utf8mb4;
