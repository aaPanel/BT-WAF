-- 创建自定义规则表
create table if not exists bt_customize_rules (
    id integer primary key autoincrement, -- 自定义规则ID
    is_global integer not null default 1, -- 是否全局规则
    src integer not null default 0, -- 自定义规则来源 0-自定义规则 1-一键加白
    status integer not null default 1, -- 启用状态
    priority integer not null default 0, -- 优先级
    create_time integer not null default (strftime('%s')), -- 添加时间
    execute_phase text not null default 'access', -- 建议运行在此执行阶段
    name text not null default '', -- 规则名称
    servers text not null default '', -- 关联的网站列表
    action text not null default '{}', -- 匹配后的执行动作
    root text not null default '{}' -- 根结点
);

-- 创建自定义规则表索引
create index if not exists customizeRules_status_isGlobal_priority_createTime_name on bt_customize_rules (status, is_global, priority, create_time, name);

-- 创建网站-规则关联表
create table if not exists bt_customize_rule_website (
    rule_id integer, -- 自定义规则ID
    server_name text not null default '' -- 网站名称（唯一标识）
);

-- 创建网站-规则关联表索引
create unique index if not exists customizeRuleWebsite_ruleId_serverName on bt_customize_rule_website (rule_id, server_name);