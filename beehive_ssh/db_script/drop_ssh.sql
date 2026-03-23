-- -- elenco tabelle dello schema
-- select t.TABLE_NAME
-- from information_schema.TABLES t
-- where t.TABLE_SCHEMA = 'auth_stage'

-- -- foglie
-- select t.TABLE_NAME -- , t.*
-- from information_schema.TABLES t
-- where 1=1
-- and t.TABLE_SCHEMA = 'auth_stage'
-- and not exists (
-- 	select *
-- 	from information_schema.KEY_COLUMN_USAGE kcu
-- 	where REFERENCED_TABLE_SCHEMA = 'auth_stage'
-- 	and kcu.REFERENCED_TABLE_NAME = t.TABLE_NAME
-- 	-- and kcu.TABLE_NAME not in ( <<<foglie>>> )
-- )
-- -- and t.TABLE_NAME not in ( <<<foglie>>> )
-- order by t.TABLE_TYPE DESC, t.TABLE_NAME

DROP TABLE IF EXISTS ssh_stage.configuration;
DROP TABLE IF EXISTS ssh_stage.groups_nodes;
DROP TABLE IF EXISTS ssh_stage.keys_users;
DROP TABLE IF EXISTS ssh_stage.perm_tag;
DROP TABLE IF EXISTS ssh_stage.perm_tag_entity;
DROP TABLE IF EXISTS ssh_stage.scheduler_step;
DROP TABLE IF EXISTS ssh_stage.scheduler_task;
DROP TABLE IF EXISTS ssh_stage.scheduler_trace;

DROP TABLE IF EXISTS ssh_stage.ssh_group;
DROP TABLE IF EXISTS ssh_stage.ssh_key;
DROP TABLE IF EXISTS ssh_stage.ssh_user;

DROP TABLE IF EXISTS ssh_stage.ssh_login;

DROP TABLE IF EXISTS ssh_stage.ssh_node;
