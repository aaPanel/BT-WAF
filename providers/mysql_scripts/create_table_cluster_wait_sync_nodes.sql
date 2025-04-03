-- 创建网站同步任务表
create table if not exists `wait_sync_nodes` (
    `id` int unsigned primary key auto_increment,
    `site_id` varchar(32) not null default '' comment '网站id --当不为空时，表示节点需要删除此网站',
    `node_id` varchar(32) not null default '' comment '节点id',
    `create_time` int unsigned not null default 0 comment '添加时间',
    index `idx_sid` (`node_id`)
    ) charset=utf8mb4;
