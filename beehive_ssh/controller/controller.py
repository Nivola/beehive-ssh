# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte

from copy import deepcopy
from typing import List
from base64 import b64encode
from six.moves.urllib.parse import urlencode
from six import StringIO, ensure_binary
import ujson as json
from typing import Tuple, List, Union
from beehive.common.apiclient import BeehiveApiClientError
from beehive.common.apimanager import ApiObject, ApiController, ApiManagerError
from beehive.common.event import Event
from beehive.common.data import trace, TransactionError, operation
from beecell.types.type_dict import dict_get
from beecell.types.type_id import id_gen
from beecell.types.type_string import truncate
from paramiko import DSSKey, ECDSAKey, RSAKey
from paramiko.ssh_exception import SSHException
from beehive_ssh.dao.SshDao import SshDbManager
from beehive_ssh.model import SshGroup, SshNode, SshUser, SshKey
from beehive_ssh.controller.group import ApiSshGroup
from beehive_ssh.controller.key import ApiSshKey
from beehive_ssh.controller.node import ApiSshNode
from beehive_ssh.controller.user import ApiSshUser
from beehive_ssh.controller.object import SshApiObject


class SshController(ApiController):
    """Service Module controller."""

    version = "v1.0"

    def __init__(self, module):
        ApiController.__init__(self, module)

        self.manager = SshDbManager()

        self.child_classes = [ApiSshGroup, ApiSshKey]

    def populate(self, db_uri):
        """Populate initial data in service database

        :param db_uri: database uri
        :return:
        """
        self.manager.populate(db_uri)

    @trace(entity="ApiSshGroup", op="view")
    def get_ansible_inventory(self, group=None, node=None, node_name=None):
        """Get ansible dynamic inventory.

        :param node: node reference
        :param group: group reference
        :param node_name: node name pattern
        :return: dict with ansible inventory
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        objs = self.can("view", objtype=SshApiObject.objtype)

        # get filters
        if group is not None:
            group = self.get_ssh_group(group).oid
        elif node is not None:
            node = self.get_ssh_node(node).oid

        # query database
        nodegroups = self.manager.get_nodes_and_groups(node=node, group=group, node_name=node_name)
        inventory_dict = {
            "all": {
                "hosts": [],
                "vars": {
                    "ansible_user": None,
                    #'ansible_ssh_private_key_file': None,
                    #'ansible_ssh_private_key_files': {},
                },
            },
            "_meta": {"hostvars": {}},
        }

        # function to check permissions
        def check(objs, objdef, objid):
            objset = set(objs.get(objdef.lower(), []))

            # create needs
            needs = self.get_needs(objid.split("//"))

            # check if needs overlaps perms
            res = self.has_needs(needs, objset)
            return res

        for nodegroup in nodegroups:
            node = nodegroup[0]
            user = nodegroup[1]
            key = nodegroup[2]
            group = nodegroup[3]

            # check authorization for group
            # self.logger.debug2('Check group permission for group %s' % group.objid)
            if check(objs, ApiSshGroup.objdef, group.objid) is False:
                continue

            # check authorization for key
            if key is not None:
                # self.logger.debug2('Check key permission for key %s' % key.objid)
                if check(objs, ApiSshKey.objdef, key.objid) is False:
                    continue

            # append to all group
            if node.name not in inventory_dict["all"]["hosts"]:
                inventory_dict["all"]["hosts"].append(node.name)

            try:
                inventory_dict[group.name]["hosts"].append(node.name)
            except:
                inventory_dict[group.name] = {"hosts": [node.name]}

            vars = {
                "ansible_user": user.username,
                "ansible_password": self.decrypt_data(user.password),
            }
            if key is not None:
                vars["ansible_user_key_uuid"] = key.uuid
            inventory_dict["_meta"]["hostvars"][node.name] = vars
            # inventory_dict['all']['vars']['ansible_ssh_private_key_files'][key.name] = key.priv_key

        return inventory_dict

    @trace(entity="ApiSshGroup", op="view")
    def get_ssh_group(self, oid: Union[str, int]) -> ApiSshGroup:
        """Get single ssh group.

        :param oid: entity model id, uuid
        :return: SshGroup
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        ssh_group = self.get_entity(ApiSshGroup, SshGroup, oid)
        return ssh_group

    @trace(entity="ApiSshGroup", op="view")
    def get_paginated_ssh_groups(self, *args, **kvargs) -> Tuple[List[ApiSshGroup], int]:
        def findSshGroups(*args, **kvargs):
            entities, total = self.manager.get_paginated_ssh_groups(*args, **kvargs)
            return entities, total

        res, total = self.get_paginated_entities(ApiSshGroup, findSshGroups, *args, **kvargs)
        return res, total

    @trace(entity="ApiSshNode", op="view")
    def get_ssh_node(self, oid: Union[str, int]) -> ApiSshNode:
        """Get single ssh group.

        Args:
            oid (_type_): entity model id, uuid

        Raises:
            ApiManagerError: raise :class:`ApiManagerError`

        Returns:
             SshNode: _description_
        """
        ssh_node = self.get_entity(ApiSshNode, SshNode, oid)
        return ssh_node

    @trace(entity="ApiSshNode", op="view")
    def get_ssh_nodes(self, *args, **kvargs) -> Tuple[List[ApiSshNode], int]:
        """get list of nodes and number of items that match the request
        may recive pagination arguments
        :param page: query page [default=0]
        :param size: query size [default=20]

        Returns:
            Tuple[List[ApiSshNode], int]: _description_
        """

        def find_ssh_nodes(*args, **kvargs):
            group_id = kvargs.get("group_id", None)
            if group_id is not None:
                kvargs["group_id"] = self.get_ssh_group(group_id).oid

            key_id = kvargs.get("key_id", None)
            if key_id is not None:
                kvargs["key_id"] = self.get_ssh_key(key_id).oid

            entities, total = self.manager.get_paginated_nodes(*args, **kvargs)
            return entities, total

        res, total = self.get_paginated_entities(ApiSshNode, find_ssh_nodes, *args, **kvargs)
        return res, total

    @trace(entity="ApiSshNode", op="use")
    def get_ssh_node_actions(self, node_id=None, *args, **kvargs) -> Tuple[List[dict], int]:
        """Get node actions
        may recive pagination arguments


        :param date: day to query. Syntax YYYY.MM.DD
        :param page: query page [default=0]
        :param size: query size [default=20]
        :return:
        """
        self.can("use", objtype=ApiSshNode.objtype, definition=ApiSshNode.objdef).get(ApiSshNode.objdef)

        kvargs = {
            "date": kvargs.get("date"),
            "size": kvargs.get("size"),
            "page": kvargs.get("page"),
            "event_type": "SSH",
            "input": node_id,
        }
        events = Event.get_from_elastic(self.api_manager.app_env, self.api_manager.elasticsearch, **kvargs)
        res = []
        for event in events.get("values"):
            data = event.data
            params = json.loads(data.get("kwargs", "{}"))
            status = data.get("response", None)
            if status[0] is True:
                status = "OK"
            else:
                msg = ""
                if isinstance(status, list):
                    msg = " - %s" % status[1]
                status = "KO" + msg
            res.append(
                {
                    "id": event.id,
                    "date": event.creation,
                    "user": event.source,
                    "action_id": data.get("opid", None),
                    "action": data.get("op", None),
                    "elapsed": data.get("elapsed", None),
                    "node_id": params.get("node_id", None),
                    "node_name": params.get("node_name", None),
                    "node_user": params.get("user", "").split(".")[0],
                    "status": status,
                }
            )
        return res, events.get("total")

    @trace(entity="ApiSshUser", op="view")
    def get_ssh_user(self, oid: Union[str, int]) -> ApiSshUser:
        """Get single ssh user.

        :param oid: entity model id, uuid
        :return: SshUser
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """

        def find_ssh_users(*args, **kvargs):
            kvargs["user_id"] = oid
            entities, total = self.manager.get_paginated_users(*args, **kvargs)
            return entities, total

        entities, total = self.get_paginated_entities(ApiSshUser, find_ssh_users)
        if total == 0:
            raise ApiManagerError("Ssh node user %s was not found" % oid)
        ssh_user = entities[0]
        # ssh_user = self.get_entity(ApiSshUser, SshUser, oid)
        return ssh_user

    @trace(entity="ApiSshUser", op="view")
    def get_ssh_users(self, *args, **kvargs) -> Tuple[List[ApiSshUser], int]:
        """List users
        may recive pagination arguments

        :param args:
        :param kvargs:
        :param page: query page [default=0]
        :param size: query size [default=20]
        :return:
        """

        def find_ssh_users(*args, **kvargs):
            node_id = kvargs.pop("node_id", None)
            if node_id is not None:
                kvargs["node_id"] = self.get_ssh_node(node_id).oid

            entities, total = self.manager.get_paginated_users(*args, **kvargs)
            return entities, total

        res, total = self.get_paginated_entities(ApiSshUser, find_ssh_users, *args, **kvargs)
        return res, total

    @trace(entity="ApiSshKey", op="view")
    def get_ssh_key(self, oid: Union[str, int]) -> ApiSshKey:
        """Get single ssh key.

        :param oid: entity model id, uuid
        :return: SshKey
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """

        ssh_key = self.get_entity(ApiSshKey, SshKey, oid)
        return ssh_key

    @trace(entity="ApiSshKey", op="view")
    def get_ssh_keys(self, *args, **kvargs) -> Tuple[List[ApiSshKey], int]:
        """Get ssh keys

        :param args:
        :param kvargs:
        :return:
        """

        def find_sh_keys(*args, **kvargs):
            user_id = kvargs.pop("user_id", None)
            if user_id is not None:
                kvargs["user_id"] = self.get_ssh_user(user_id).oid
            names = kvargs.get("key_names", None)
            if names is not None:
                kvargs["names"] = names.split(",")

            entities, total = self.manager.get_paginated_keys(*args, **kvargs)
            return entities, total

        res, total = self.get_paginated_entities(ApiSshKey, find_sh_keys, *args, **kvargs)
        return res, total

    @trace(entity="ApiSshGroup", op="insert")
    def add_ssh_group(self, name: str, desc: str = "", attribute=None, active=True):
        """Add new group.

        :param name: group name
        :param desc: group description
        :param attribute: group attribute values
        :return: group uuid
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        # check authorization
        if operation.authorize is True:
            self.check_authorization(ApiSshGroup.objtype, ApiSshGroup.objdef, None, "insert")

        try:
            objid = "%s" % id_gen()
            group = SshGroup(objid, name=name, desc=desc, active=active, attribute=attribute)
            self.manager.add(group)
            # add object and permission
            ApiSshGroup(self, oid=group.id).register_object(objid.split("//"), desc=name)
            self.logger.debug("Ssh add new ssh_group: %s" % name)

            # self.awx_client.add_team(name, description=desc)

            return group.uuid
        except TransactionError as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=ex.code)
        except Exception as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=400)

    @trace(entity="ApiSshNode", op="insert")
    def add_ssh_node(
        self,
        group_id: Union[str, int],
        name: str,
        node_type: str = "",
        ip_address: str = "",
        desc: str = "",
        attribute=None,
        active=True,
    ) -> str:
        """Add new node.

        :param name: sshnode name
        :param group_id: group group_id group identity
        :param node_type: sshnode type of node
        :param ip_address: sshnode ip_address of the node
        :param desc: sshnode generic description
        :param attribute: sshnode attribute values
        :return: node uuid
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        group = self.get_ssh_group(group_id)

        # check authorization
        if operation.authorize is True:
            self.check_authorization(ApiSshNode.objtype, ApiSshNode.objdef, group.objid, "insert")
        try:
            objid = "%s//%s" % (group.objid, id_gen())
            node = SshNode(objid, name, active, desc, attribute, node_type, ip_address, group.model)
            self.manager.add(node)
            # if group:
            #     node.groups.append(group.model)
            # add object and permission
            ApiSshNode(self, oid=node.id).register_object(objid.split("//"), desc=name)

            self.logger.debug("Add new ssh_node: %s" % name)
            return node.uuid
        except TransactionError as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=ex.code)
        except Exception as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=400)

    @trace(entity="ApiSshUser", op="insert")
    def add_ssh_user(
        self,
        node_id: Union[str, int],
        key_id: Union[str, int],
        name: str,
        username: str,
        password: str,
        attribute,
        desc="",
    ) -> str:
        """Add new user.

        :param name: sshuser name
        :param node_id: sshuser node_id sshnode identity
        :param key_id: sshkey key_id oid key identity
        :param username: sshuser username
        :param password: sshuser password user
        :param attribute: sshuser attribute values
        :return: user uuid
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        node = self.get_ssh_node(node_id)

        # check authorization
        if operation.authorize is True:
            self.check_authorization(ApiSshUser.objtype, ApiSshUser.objdef, node.objid, "insert")
        try:
            objid = "%s//%s" % (node.objid, id_gen())
            password = self.encrypt_data(password)
            user = SshUser(objid, name, username, password, attribute, desc)
            user.node_id = node.oid
            if key_id is not None:
                key = self.get_ssh_key(key_id)
                user.key.append(key.model)
            else:
                self.logger.warn("Ssh key was not specified for user %s" % name)

            self.manager.add(user)
            # add object and permission

            ApiSshUser(self, oid=user.id).register_object(objid.split("//"), desc=name)

            self.logger.debug("Add new ssh_user: %s" % name)
            return user.uuid
        except TransactionError as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=ex.code)
        except Exception as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=400)

    @trace(entity="ApiSshKey", op="insert")
    def add_ssh_key(
        self,
        priv_key: str = None,
        pub_key: str = None,
        type: str = "rsa",
        bits: int = 4096,
        name: str = None,
        desc: str = "",
        attribute=None,
    ):
        """Add new key.

        :param name: sshkey name
        :param priv_key: sshkey private key. Use for existing key [optional]
        :param pub_key: sshkey public key. Use with priv_key for existing key [optional]
        :param type: For new key specify type like rsa, dsa. Use for new key when priv_key is None [default=rsa]
        :param bits: For new key specify bits like 4096. Use with type [default=4096]
        :param desc: sshkey description
        :param attribute: sshkey attribute values
        :return: sshkey uuid
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        # check authorization
        if operation.authorize is True:
            self.check_authorization(ApiSshKey.objtype, ApiSshKey.objdef, None, "insert")

        try:
            objid = "%s" % (id_gen())
            if priv_key is None:
                # create new priv e pub key
                key_dispatch_table = {"dsa": DSSKey, "rsa": RSAKey, "ECDSA": ECDSAKey}

                if type not in key_dispatch_table:
                    raise SSHException("Unknown %s algorithm to generate keys pair" % type)

                # generating private key
                prv = key_dispatch_table[type].generate(bits=bits)
                file_obj = StringIO()
                prv.write_private_key(file_obj)
                priv_key = b64encode(ensure_binary(file_obj.getvalue()))
                file_obj.close()

                # get public key
                ssh_key = "%s %s" % (prv.get_name(), prv.get_base64())
                pub_key = b64encode(ensure_binary(ssh_key))
            # else:
            #     raise Exception('Secret key or key type must be specified')
            key = SshKey(objid, priv_key, pub_key, name, desc, attribute)
            self.manager.add(key)

            # add object and permission
            ApiSshKey(self, oid=key.id).register_object(objid.split("//"), desc=name)

            # self.awx_client.add_ssh_credentials(name=name, description=desc,
            #                                     ssh_key_data=priv_key,
            #                                     username="root", password=None,
            #                                     become_method='sudo',
            #                                     organizationid=self.awx_client.organization)

            self.logger.debug("Add new ssh_key: %s" % name)
            return key.uuid
        except TransactionError as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=ex.code)
        except Exception as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=400)

    # Questa sara la add key
    def create_ssh_key(self):
        pass
