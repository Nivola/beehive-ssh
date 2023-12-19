# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2023 CSI-Piemonte
from re import match

from beecell.db import ModelError
from beecell.simple import truncate
from beehive.common.model import AbstractDbManager, PaginatedQueryGenerator
from sqlalchemy.engine import create_engine
import logging
from sqlalchemy import exc
from sqlalchemy.orm.session import sessionmaker
from beehive.common.data import transaction, query
from beehive_ssh.model import (
    SshGroup,
    Base,
    SshNode,
    SshUser,
    SshKey,
    BaseSshEntity,
    GroupNodes,
    KeyUsers,
    ExtendedSshUser,
)
from datetime import datetime


sshBase = Base
logger = logging.getLogger(__name__)


class SshDbManager(AbstractDbManager):
    """Ssh db manager

    :param session: sqlalchemy session
    """

    def __init__(self, session=None):
        AbstractDbManager.__init__(self, session)

    @staticmethod
    def populate(db_uri):
        """ """
        AbstractDbManager.create_table(db_uri)
        data = []

        try:
            engine = create_engine(db_uri)
            db_session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
            session = db_session()
            for item in data:
                try:
                    session.add(item)
                    logger.info("Add item : %s" % item)
                    session.commit()
                except Exception as ex:
                    session.rollback()
                    logger.warning(ex)

            logger.info("Populate tables on : %s" % db_uri)
            del engine
        except exc.DBAPIError:
            raise

    @staticmethod
    def create_table(db_uri):
        """Create all tables in the engine. This is equivalent to "Create Table" statements in raw SQL

        :param db_uri: db uri
        """
        AbstractDbManager.create_table(db_uri)

        try:
            engine = create_engine(db_uri)
            engine.execute("SET FOREIGN_KEY_CHECKS=1;")
            Base.metadata.create_all(engine)
            logger.info("Create tables on : %s" % db_uri)
            del engine
        except exc.DBAPIError as e:
            raise Exception(e)

    @staticmethod
    def remove_table(db_uri):
        """Remove all tables in the engine. This is equivalent to "Drop Table" statements in raw SQL

        :param db_uri: db uri
        """
        AbstractDbManager.remove_table(db_uri)

        try:
            engine = create_engine(db_uri)
            engine.execute("SET FOREIGN_KEY_CHECKS=0;")
            Base.metadata.drop_all(engine)
            logger.info("Remove tables from : %s" % db_uri)
            del engine
        except exc.DBAPIError as e:
            raise Exception(e)

    @transaction
    def delete_ssh_group(self, *args, **kvargs):
        """Remove Division.

        :param int oid: entity id. [optional]
        :return: :class:`Division`
        :raises TransactionError: raise :class:`TransactionError`
        """
        res = self.remove_entity(SshGroup, *args, **kvargs)
        return res

    def update_ssh_group(self, *args, **kvargs):
        res = self.update_entity(SshGroup, *args, **kvargs)
        return res

    def update_ssh_node(self, *args, **kvargs):
        res = self.update_entity(SshNode, *args, **kvargs)
        return res

    def update_ssh_user(self, *args, **kvargs):
        res = self.update_entity(SshUser, *args, **kvargs)
        return res

    def update_ssh_key(self, *args, **kvargs):
        res = self.update_entity(SshKey, *args, **kvargs)
        return res

    # def update_ssh_login(self, *args, **kvargs):
    #     res = self.update_entity(SshLogin, *args, **kvargs)
    #     return res

    @transaction
    def get_object(self, entity_class, *args, **kvargs):
        """Get only one or none filtered entity_class.

        :return: one of entity_class
        :raises TransactionError: raise :class:`TransactionError`
        """
        session = self.get_session()
        query = session.query(entity_class)
        query = self.add_base_entity_filters(query, *args, **kvargs)

        obj = query.one_or_none()
        return obj

    @transaction
    def add_node_to_group(self, node, group):
        """Add a node to a group.

        :param node: ssh node model
        :param group: ssh group model
        :return: True if operation is successful, False otherwise
        :rtype: bool
        :raises TransactionError: raise :class:`TransactionError`
        """
        session = self.get_session()
        groups = node.groups
        if group not in groups:
            groups.append(group)
            self.logger.debug("Add node %s to group %s" % (node, group))
        else:
            self.logger.warning("Node %s already exists in group %s" % (node.uuid, group.uuid))
            raise ModelError("Node %s already exists in group %s" % (node.uuid, group.uuid), code=400)

        return True

    @transaction
    def remove_node_from_group(self, node, group):
        """Remove a node from a group.

        :param node: ssh node model
        :param group: ssh group model
        :return: True if operation is successful, False otherwise
        :rtype: bool
        :raises TransactionError: raise :class:`TransactionError`
        """
        session = self.get_session()
        groups = node.groups
        main_group_objid = node.objid.split("//")[0]
        if main_group_objid == group.objid:
            raise ModelError(
                "Group %s is the main group of node %s. It can not be removed" % (group.uuid, node.uuid),
                code=400,
            )
        try:
            idx = groups.index(group)
            groups.pop(idx)
            self.logger.debug("Remove node %s from group %s" % (node.uuid, group.uuid))
        except:
            raise ModelError("Node %s not in group %s" % (node.uuid, group.uuid), code=400)
        return True

    @query
    def get_paginated_nodes(self, *args, **kvargs):
        """Get paginated SshNode.

        :param group_id: SshGroup id [optional]
        :param ip_address: ip_address [optional]
        :param page: entities list page to show [default=0]
        :param size: number of entities to show in list per page [default=10, 0 => no pagination]
        :param order: sort order [default=DESC]
        :param field: sort field [default=id]
        :return: list of paginated SshNode
        :raises TransactionError: raise :class:`TransactionError`
        """
        filters = BaseSshEntity.get_base_entity_sqlfilters(*args, **kvargs)
        tables = []

        if kvargs.get("names", None) is not None:
            kvargs["names"] = "%" + kvargs["names"] + "%"
            filters.append("AND name like :names")

        if kvargs.get("ip_address", None) is not None:
            filters.append("AND ip_address= :ip_address")

        if kvargs.get("group_id", None) is not None:
            filters.append(" AND t3.id=t4.fk_node_id")
            filters.append(" AND t4.fk_group_id=t5.id")
            filters.append(" AND t4.fk_group_id=:group_id")
            tables = [("groups_nodes", "t4"), ("ssh_group", "t5")]

        if kvargs.get("key_id", None) is not None:
            filters.append(" AND t3.id=t4.fk_node_id")
            filters.append(" AND t4.id=t5.fk_user_id")
            filters.append(" AND t5.fk_key_id=:key_id")
            tables = [("ssh_user", "t4"), ("keys_users", "t5")]

        res, total = self.get_api_bo_paginated_entities(SshNode, filters=filters, tables=tables, *args, **kvargs)
        return res, total

    @query
    def get_node_users(self, node_id=None, *args, **kvargs):
        """Get node SshUsers.

        :param node_id: SshNode id [optional]
        :param username: user name [optional]
        :param page: entities list page to show [default=0]
        :param size: number of entities to show in list per page [default=10, 0 => no pagination]
        :param order: sort order [default=DESC]
        :param field: sort field [default=id]
        :return: list of paginated SshUser
        :raises TransactionError: raise :class:`TransactionError`
        """
        session = self.get_session()
        filters = BaseSshEntity.get_base_entity_sqlfilters(*args, **kvargs)
        query = PaginatedQueryGenerator(SshUser, session, with_perm_tag=False)
        query.add_join("ssh_node", "t4", "t3.fk_node_id=t4.id", left=False, inner=True, outer=False)
        query.set_pagination(page=0, size=0, order="DESC", field="id")
        filters.append(" AND fk_node_id= :node_id")
        kvargs["node_id"] = node_id

        for filter in filters:
            query.add_filter(filter)

        res, total = query.run2(None, *args, **kvargs)

        self.logger.debug2("Get ssh users: %s" % res)
        return res, total

    @query
    def get_paginated_users(
        self,
        node_id=None,
        tags=None,
        page=0,
        size=10,
        order="DESC",
        field="id",
        username=None,
        user_id=None,
        *args,
        **kvargs,
    ):
        """Get paginated SshUser.

        :param node_id: SshNode id [optional]
        :param username: user name [optional]
        :param user_id: user id or uuid [optional]
        :param page: entities list page to show [default=0]
        :param size: number of entities to show in list per page [default=10, 0 => no pagination]
        :param order: sort order [default=DESC]
        :param field: sort field [default=id]
        :param with_perm_tag: if False don't use permission tags [optional]
        :return: list of paginated SshUser
        :raises TransactionError: raise :class:`TransactionError`
        """
        session = self.get_session()
        filters = BaseSshEntity.get_base_entity_sqlfilters(*args, **kvargs)
        query = PaginatedQueryGenerator(ExtendedSshUser, session, with_perm_tag=kvargs.get("with_perm_tag", True))
        query.add_join("ssh_node", "t4", "t3.fk_node_id=t4.id", left=False, inner=True, outer=False)
        query.add_join(
            "keys_users",
            "t6",
            "t6.fk_user_id=t3.id",
            left=True,
            inner=False,
            outer=True,
        )
        query.add_join("ssh_key", "t5", "t6.fk_key_id=t5.id", left=True, inner=False, outer=True)
        query.set_pagination(page=page, size=size, order=order, field=field)
        query.add_select_field("t4.name as node_name")
        query.add_select_field("t5.uuid as key_id")
        query.add_select_field("t5.name as key_name")

        if "filter_expired" in kvargs and kvargs.get("filter_expired") is not None:
            kvargs.update(filter_expiry_date=datetime.today())

        if user_id is not None:
            if isinstance(user_id, int):
                user_id = str(user_id)
            kvargs["user_id"] = user_id

            # get obj by uuid
            if match("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", user_id):
                filters.append("AND t3.uuid= :user_id")
            # get obj by id
            elif match("^\d+$", user_id):
                filters.append("AND t3.id= :user_id")
            # get obj by name
            elif match("[\-\w\d]+", user_id):
                filters.append("AND t3.name= :user_id")

        if username is not None:
            filters.append("AND username= :username")
            kvargs["username"] = username

        if node_id is not None:
            filters.append(" AND fk_node_id= :node_id")
            kvargs["node_id"] = node_id

        for filter in filters:
            query.add_filter(filter)

        res, total = query.run2(tags, *args, **kvargs)

        self.logger.debug2("Get ssh users: %s" % res)
        return res, total

    @query
    def get_paginated_keys(self, *args, **kvargs):
        """Get paginated SshKey.

        :param user_id: SshUser id [optional]
        :param page: entities list page to show [default=0]
        :param size: number of entities to show in list per page [default=10, 0 => no pagination]
        :param order: sort order [default=DESC]
        :param field: sort field [default=id]
        :return: list of paginated SshKey
        :raises TransactionError: raise :class:`TransactionError`
        """
        filters = BaseSshEntity.get_base_entity_sqlfilters(*args, **kvargs)
        tables = []
        if "user_id" in kvargs:
            filters.append(" AND t3.id=t4.fk_key_id")
            filters.append(" AND t4.fk_user_id=t5.id")
            filters.append(" AND t5.id=:user_id")
            tables = [("keys_users", "t4"), ("ssh_user", "t5")]

        res, total = self.get_api_bo_paginated_entities(SshKey, filters=filters, tables=tables, *args, **kvargs)
        return res, total

    def get_paginated_ssh_groups(self, *args, **kvargs):
        """Get groups.

        :param page: entities list page to show [default=0]
        :param size: number of entities to show in list per page [default=0]
        :param order: sort order [default=DESC]
        :param field: sort field [default=id]
        :return: list of SshGroup
        :raises QueryError: raise :class:`QueryError`
        """
        filters = BaseSshEntity.get_base_entity_sqlfilters(*args, **kvargs)
        res, total = self.get_api_bo_paginated_entities(SshGroup, filters=filters, *args, **kvargs)
        return res, total

    def get_api_bo_paginated_entities(self, entity, filters, *args, **kvargs):
        if "filter_expired" in kvargs and kvargs.get("filter_expired") is not None:
            kvargs.update(filter_expiry_date=datetime.today())

        res, total = self.get_paginated_entities(entity, filters=filters, *args, **kvargs)
        return res, total

    def get_nodes_and_groups(self, users=["root", "centos", "administrator"], group=None, node=None, node_name=None):
        """Get nodes and groups

        :param users: list of user for nodes
        :param group: group id filter [optional]
        :param node: node id filter [optional]
        :param node_name: node name pattern [optional]
        :return:
        """
        session = self.get_session()
        data = (
            session.query(SshNode, SshUser, SshKey, SshGroup)
            .join(SshUser, SshUser.node_id == SshNode.id)
            .join(GroupNodes, GroupNodes.fk_node_id == SshNode.id)
            .join(SshGroup, GroupNodes.fk_group_id == SshGroup.id)
            .outerjoin(KeyUsers, KeyUsers.fk_user_id == SshUser.id)
            .outerjoin(SshKey, KeyUsers.fk_key_id == SshKey.id)
            .filter(SshNode.expiry_date == None)
            .filter(SshUser.expiry_date == None)
            .filter(SshUser.username.in_(users))
            .filter(SshGroup.expiry_date == None)
        )

        if group is not None:
            data = data.filter(SshGroup.id == group)
        if node is not None:
            data = data.filter(SshNode.id == node)
        if node_name is not None:
            data = data.filter(SshNode.name.like("%" + node_name + "%"))

        data = data.all()
        self.logger.debug("Get node groups: %s" % truncate(data))

        return data
