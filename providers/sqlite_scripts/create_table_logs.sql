-- 创建操作日志表
create table if not exists bt_logs (
    id integer primary key autoincrement, -- 主键ID
    uid integer not null default 0, -- 操作人 0-系统
    log_type integer not null default 0, -- 日志类型 0-系统日志
    content text not null default '', -- 日志内容
    create_time integer not null default (strftime('%s')) -- 日志时间
);

-- 创建索引
create index if not exists `logs_createTime_logType_uid` on `bt_logs` (`create_time`, `log_type`, `uid`);