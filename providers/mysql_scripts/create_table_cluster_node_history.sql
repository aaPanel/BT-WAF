-- 创建节点历史数据相关表
-- @author Zhj<2023-12-20>

-- 节点QPS历史记录（每分钟）
create table if not exists `cluster_node_qps_per_minutes` (
    `node_id` int unsigned not null default 0 comment '节点ID',
    `qps` int unsigned not null default 0 comment 'qps',
    `create_time` int unsigned not null default 0 comment '添加时间（Unix时间戳 精确到分钟级别）',
    primary key (`node_id`, `create_time`),
    index `idx_chart` (`create_time`, `qps`, `node_id`)
) charset=utf8mb4;

-- 节点回源耗时历史记录（每分钟）
create table if not exists `cluster_node_resource_time_per_minutes` (
    `node_id` int unsigned not null default 0 comment '节点ID',
    `resource_time` int unsigned not null default 0 comment '回源耗时ms',
    `create_time` int unsigned not null default 0 comment '添加时间（Unix时间戳 精确到分钟级别）',
    primary key (`node_id`, `create_time`),
    index `idx_chart` (`create_time`, `resource_time`, `node_id`)
) charset=utf8mb4;

-- 节点网站流量历史记录（每分钟）
create table if not exists `cluster_node_website_flow_per_minutes` (
    `node_id` int unsigned not null default 0 comment '节点ID',
    `upload` bigint unsigned not null default 0 comment '网站流量上行byte',
    `download` bigint unsigned not null default 0 comment '网站流量下行byte',
    `create_time` int unsigned not null default 0 comment '添加时间（Unix时间戳 精确到分钟级别）',
    primary key (`node_id`, `create_time`),
    index `idx_chart` (`create_time`, `upload`, `download`, `node_id`)
) charset=utf8mb4;

-- 节点请求状态码历史记录（每分钟）
create table if not exists `cluster_node_errcode_per_minutes` (
    `node_id` int unsigned not null default 0 comment '节点ID',
    `err_40x` int unsigned not null default 0 comment '40x错误码',
    `err_499` int unsigned not null default 0 comment '499错误码',
    `err_500` int unsigned not null default 0 comment '500错误码',
    `err_502` int unsigned not null default 0 comment '502错误码',
    `err_503` int unsigned not null default 0 comment '503错误码',
    `err_504` int unsigned not null default 0 comment '504错误码',
    `total_request` int unsigned not null default 0 comment '总请求数',
    `create_time` int unsigned not null default 0 comment '添加时间（Unix时间戳 精确到分钟级别）',
    primary key (`node_id`, `create_time`),
    index `idx_chart` (`create_time`, `err_40x`, `err_499`, `err_500`, `err_502`, `err_503`, `err_504`, `total_request`, `node_id`)
) charset=utf8mb4;

-- 节点主机资源历史记录（每分钟）
create table if not exists `cluster_node_system_per_minutes` (
    `node_id` int unsigned not null default 0 comment '节点ID',
    `cpu` decimal(5,2) not null default 0 comment 'CPU占用率',
    `mem` decimal(5,2) not null default 0 comment '内存占用率',
    `upload` bigint unsigned not null default 0 comment '上行流量byte',
    `download` bigint unsigned not null default 0 comment '下行流量byte',
    `create_time` int unsigned not null default 0 comment '添加时间（Unix时间戳 精确到分钟级别）',
    primary key (`node_id`, `create_time`),
    index `idx_chart` (`create_time`, `cpu`, `mem`, `upload`, `download`, `node_id`)
) charset=utf8mb4;

-- 节点磁盘资源历史记录（每分钟）
create table if not exists `cluster_node_disk_per_minutes` (
    `node_id` int unsigned not null default 0 comment '节点ID',
    `mountpoint` varchar(64) not null default '' comment '磁盘挂载点',
    `read` bigint unsigned not null default 0 comment '读取速率byte',
    `write` bigint unsigned not null default 0 comment '写入速率byte',
    `used` bigint unsigned not null default 0 comment '磁盘占用byte',
    `create_time` int unsigned not null default 0 comment '添加时间（Unix时间戳 精确到分钟级别）',
    primary key (`node_id`, `mountpoint`, `create_time`),
    index `idx_chart` (`create_time`, `mountpoint`, `read`, `write`, `used`, `node_id`)
) charset=utf8mb4;