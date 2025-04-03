-- 创建证书信息表
create table if not exists `ssl_email` (
   `id` int unsigned primary key auto_increment,
   `ssl_email` varchar(255) not null default '' comment '邮箱账户',
   `create_time` int unsigned not null default 0 comment '添加时间',
   index `idx_sslEmail` (`ssl_email`)
) charset=utf8mb4;
