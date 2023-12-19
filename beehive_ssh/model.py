# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2023 CSI-Piemonte

from sqlalchemy.ext.declarative import declarative_base
from beehive.common.model import BaseEntity
import logging
from sqlalchemy import Column, Integer, Text, Table, ForeignKey, String
from sqlalchemy.orm import relationship, backref, relation

Base = declarative_base()

logger = logging.getLogger(__name__)


class GroupNodes(Base):
    __tablename__ = "groups_nodes"
    __table_args__ = {"mysql_engine": "InnoDB"}

    id = (Column("id", Integer, primary_key=True),)
    fk_group_id = Column(Integer, ForeignKey("ssh_group.id"), primary_key=True)
    fk_node_id = Column(Integer, ForeignKey("ssh_node.id"), primary_key=True)


class KeyUsers(Base):
    __tablename__ = "keys_users"
    __table_args__ = {"mysql_engine": "InnoDB"}

    id = (Column("id", Integer, primary_key=True),)
    fk_key_id = Column(Integer, ForeignKey("ssh_key.id"), primary_key=True)
    fk_user_id = Column(Integer, ForeignKey("ssh_user.id"), primary_key=True)


class BaseSshEntity(BaseEntity):
    attribute = Column(String(4000))

    def __init__(self, objid, name="", desc=None, active=True, attribute=None):
        BaseEntity.__init__(self, objid, name, desc, active)
        self.attribute = attribute


class SshGroup(Base, BaseSshEntity):
    __tablename__ = "ssh_group"

    # nodes = relationship('SshNode', secondary='groups_nodes', backref=backref('SshGroup', lazy='dynamic'))

    def __init__(self, objid, name="", desc=None, active=True, attribute=None):
        BaseSshEntity.__init__(self, objid, name, desc, active, attribute)

    def __repr__(self):
        return BaseSshEntity.__repr__(self)


class SshUser(Base, BaseSshEntity):
    """Create new node user

    :param objid: authorization id
    :param username: name of the user
    :param active: set if user is active [default=True]
    :param password: user password [optional]
    :param desc: user desc [default='']
    :param expiry_date: user expiry date [default=365 days]. Set using a datetime object
    """

    __tablename__ = "ssh_user"

    name = Column(String(200), unique=True)
    username = Column(String(255))
    password = Column(String(255))
    key = relationship("SshKey", secondary="keys_users", backref=backref("keys", lazy="dynamic"))
    node_id = Column("fk_node_id", ForeignKey("ssh_node.id"))

    def __init__(
        self,
        objid,
        name,
        username,
        password,
        attribute=None,
        desc="",
        active=True,
        expiry_date=None,
    ):
        BaseSshEntity.__init__(self, objid, name, desc, active, attribute)
        self.username = username
        self.password = password


class ExtendedSshUser(declarative_base(), BaseSshEntity):
    __tablename__ = "ssh_user"

    name = Column(String(200), unique=True)
    username = Column(String(255))
    password = Column(String(255))
    node_id = Column("fk_node_id", Integer())
    node_name = Column(String(255))
    key_name = Column(String(255))
    key_id = Column(Integer())


class SshNode(Base, BaseSshEntity):
    """Create new node

    :param objid: authorization id
    :param username: name of the user
    :param active: set if user is active [default=True]
    :param password: user password [optional]
    :param desc: user desc [default='']
    :param node_type: node type (ex: VM, Vpc,...)
    :param ip_address: ip_address of the node (ex: 0.0.0.0) [default='']
    :param expiry_date: user expiry date [default=365 days]. Set using a datetime object
    """

    __tablename__ = "ssh_node"

    name = Column(String(200), unique=True)
    node_type = Column(String(100))
    ip_address = Column(String(100))
    ssh_users = relationship("SshUser")
    groups = relationship("SshGroup", secondary="groups_nodes", backref=backref("SshNode", lazy="dynamic"))

    def __init__(
        self,
        objid,
        name="",
        active=True,
        desc="",
        attribute=None,
        node_type="",
        ip_address="",
        group=None,
    ):
        BaseSshEntity.__init__(self, objid, name, desc, active, attribute)
        self.ip_address = ip_address
        self.node_type = node_type
        self.groups = [group]


class SshKey(Base, BaseSshEntity):
    """Create new ssh key

    :param objid: authorization id
    :param name: name
    :param desc: key desc [default='']
    :param priv_key: private ssh key
    :param pub_key: public ssh key
    :param attribute: attribute
    """

    __tablename__ = "ssh_key"

    priv_key = Column(Text(5000))
    pub_key = Column(Text(5000))
    # user = relationship('SshUser', secondary='keys_users', backref=backref('users', lazy='dynamic'))

    def __init__(self, objid, priv_key, pub_key, name="", desc="", attribute=None):
        BaseSshEntity.__init__(self, objid, name=name, desc=desc, attribute=attribute)
        self.priv_key = priv_key
        self.pub_key = pub_key
