-- 创建实时数据历史记录表
create table if not exists `btwaf_realtime_history` (
    `cpu` decimal(5,2) not null default 0 comment 'CPU占用率',
    `mem` decimal(5,2) not null default 0 comment '内存占用率',
    `qps` int unsigned not null default 0 comment 'QPS',
    `download` int unsigned not null default 0 comment '网站下行流量byte',
    `upload` int unsigned not null default 0 comment '网站上行流量byte',
    `create_time` int unsigned not null default 0 comment '添加时间（Unix时间戳 精确到分钟级别）（主键）',
    primary key (`create_time`)
) charset=utf8mb4;

-- 创建磁盘实时数据历史记录表
create table if not exists `btwaf_disk_realtime_history` (
    `mountpoint` varchar(64) not null default '' comment '磁盘挂载点',
    `read` bigint unsigned not null default 0 comment '读取速率byte',
    `write` bigint unsigned not null default 0 comment '写入速率byte',
    `used` bigint unsigned not null default 0 comment '磁盘占用byte',
    `create_time` int unsigned not null default 0 comment '添加时间（Unix时间戳 精确到分钟级别）（主键）',
    primary key (`create_time`, `mountpoint`)
) charset=utf8mb4;