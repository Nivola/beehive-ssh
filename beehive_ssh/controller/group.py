# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte

# from copy import deepcopy
# from typing import List
# from base64 import b64encode
# from six.moves.urllib.parse import urlencode
# from six import StringIO, ensure_binary
# import ujson as json
from typing import Tuple, List, Union

# from beehive.common.apiclient import BeehiveApiClientError
from beehive.common.apimanager import ApiManagerError

# from beehive.common.event import Event
from beehive.common.data import trace, TransactionError

# from beecell.types.type_dict import dict_get
# from beecell.types.type_id import id_gen
# from beecell.types.type_string import truncate
# from paramiko import DSSKey, ECDSAKey, RSAKey
# from paramiko.ssh_exception import SSHException
# from beehive_ssh.dao.SshDao import SshDbManager
# from beehive_ssh.model import SshGroup, SshNode, SshUser, SshKey

from beehive_ssh.controller.object import SshApiObject

# from beehive_ssh.controller.controller import SshController


class ApiSshGroup(SshApiObject):
    objdef = "SshGroup"
    objuri = "gas/groups"
    objname = "sshgroup"
    objdesc = "sshgroup"

    role_templates = {
        "ApiSuperAdmin": {
            "desc": "Super administrator. Can all",
            "name": "ApiSuperAdminRole",
            "perms": [
                {"subsystem": "ssh", "type": "SshGroup", "objid": "*", "action": "*"},
                {
                    "subsystem": "ssh",
                    "type": "SshGroup.SshNode",
                    "objid": "*//*",
                    "action": "*",
                },
                {
                    "subsystem": "ssh",
                    "type": "SshGroup.SshNode.SshUser",
                    "objid": "*//*//*",
                    "action": "*",
                },
            ],
        },
        "master": {
            "desc": "Group administrator. Can list and update group, can list child nodes, can connect and execute "
            "command over child nodes (each users), can manage nodes, can manage node's users, can assign "
            "node to other users, can view node actions",
            "name": "GroupAdminRole",
            "perms": [
                {
                    "subsystem": "ssh",
                    "type": "SshGroup",
                    "objid": "<objid>",
                    "action": "view",
                },
                {
                    "subsystem": "ssh",
                    "type": "SshGroup",
                    "objid": "<objid>",
                    "action": "update",
                },
                {
                    "subsystem": "ssh",
                    "type": "SshGroup.SshNode",
                    "objid": "<objid>" + "//*",
                    "action": "view",
                },
                {
                    "subsystem": "ssh",
                    "type": "SshGroup.SshNode",
                    "objid": "<objid>" + "//*",
                    "action": "use",
                },
                {
                    "subsystem": "ssh",
                    "type": "SshGroup.SshNode",
                    "objid": "<objid>" + "//*",
                    "action": "update",
                },
                {
                    "subsystem": "ssh",
                    "type": "SshGroup.SshNode.SshUser",
                    "objid": "<objid>" + "//*//*",
                    "action": "*",
                },
            ],
        },
        "connect": {
            "desc": "Group connect. Can list group, can list child nodes, can connect and execute command over child "
            "nodes (each users), can view node actions",
            "name": "GroupConnectRole",
            "perms": [
                {
                    "subsystem": "ssh",
                    "type": "SshGroup",
                    "objid": "<objid>",
                    "action": "view",
                },
                {
                    "subsystem": "ssh",
                    "type": "SshGroup.SshNode",
                    "objid": "<objid>" + "//*",
                    "action": "view",
                },
                {
                    "subsystem": "ssh",
                    "type": "SshGroup.SshNode",
                    "objid": "<objid>" + "//*",
                    "action": "use",
                },
                {
                    "subsystem": "ssh",
                    "type": "SshGroup.SshNode.SshUser",
                    "objid": "<objid>" + "//*//*",
                    "action": "view",
                },
            ],
        },
        "viewer": {
            "desc": "Group viewer. Can list group, can list child nodes, can execute simple command over node (like "
            "show log) (each users)",
            "name": "GroupViewerRole",
            "perms": [
                {
                    "subsystem": "ssh",
                    "type": "SshGroup",
                    "objid": "<objid>",
                    "action": "view",
                },
                {
                    "subsystem": "ssh",
                    "type": "SshGroup.SshNode",
                    "objid": "<objid>" + "//*",
                    "action": "view",
                },
            ],
        },
    }
    role_templates_exclusions = ["ApiSuperAdmin"]

    def __init__(self, *args, **kvargs):
        """ """
        SshApiObject.__init__(self, *args, **kvargs)
        # child classes
        from beehive_ssh.controller.node import ApiSshNode

        self.child_classes = [ApiSshNode]

        self.update_object = self.manager.update_ssh_group
        self.delete_object = self.manager.delete

    def info(self):
        """Get object info

        :return: Dictionary with object info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = SshApiObject.info(self)

        return info

    def detail(self):
        """Get object extended info

        :return: Dictionary with object detail.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = self.info()
        if self.model is not None:
            info["attribute"] = self.model.attribute
        return info

    def pre_delete(self, *args, **kvargs):
        """Pre delete function. This function is used in delete method. Extend
        this function to manipulate and validate delete input params.

        :param args: custom params
        :param kvargs: custom params
        :return: kvargs
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        # get group nodes
        nodes, tot = self.controller.get_ssh_nodes(group_id=self.oid, filter_expired=False)
        if tot > 0:
            raise ApiManagerError("Ssh group %s is not empty. It contains %s nodes" % (self.uuid, tot))
        # for user in users:
        #     user.delete(soft=True)

        return kvargs

    @trace(op="node-add.update")
    def add_node(self, node):
        """Add new node to group.

        :param node: sshnode id, uuid or name
        :return: node uuid
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        self.verify_permisssions("update")

        try:
            node = self.controller.get_ssh_node(node)
            self.manager.add_node_to_group(node.model, self.model)
            self.logger.debug("Add node %s to group: %s" % (node.uuid, self.uuid))
            return node.uuid
        except TransactionError as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=ex.code)
        except Exception as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=400)

    @trace(op="node-del.update")
    def remove_node(self, node):
        """Remove new node from group.

        :param node: sshnode id, uuid or name
        :return: node uuid
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        self.verify_permisssions("update")

        try:
            node = self.controller.get_ssh_node(node)
            self.manager.remove_node_from_group(node.model, self.model)
            self.logger.debug("Remove node %s from group: %s" % (node.uuid, self.uuid))
            return node.uuid
        except TransactionError as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=ex.code)
        except Exception as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=400)
