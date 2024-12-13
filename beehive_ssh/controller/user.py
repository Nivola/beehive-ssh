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

from beehive_ssh.controller.object import SshApiObject
from beehive_ssh.controller.node import ApiSshNode


class ApiSshUser(SshApiObject):
    objdef = ApiObject.join_typedef(ApiSshNode.objdef, "SshUser")
    objuri = "gas/users"
    objname = "sshuser"
    objdesc = "sshuser"

    role_templates = {
        "connect.%s": {
            "desc": "Node connect - %s. Can list node, can connect and execute command over node, "
            "can view node actions",
            "name": "NodeConnectRole",
            "perms": [
                {
                    "subsystem": "ssh",
                    "type": "SshGroup.SshNode",
                    "objid": "<objid>",
                    "action": "view",
                },
                {
                    "subsystem": "ssh",
                    "type": "SshGroup.SshNode",
                    "objid": "<objid>",
                    "action": "use",
                },
                {
                    "subsystem": "ssh",
                    "type": "SshGroup.SshNode.SshUser",
                    "objid": "<objid2>",
                    "action": "view",
                },
            ],
        },
        "viewer.%s": {
            "desc": "Node viewer - %s. Can list node, can execute simple command over node (like show log)",
            "name": "NodeViewerRole",
            "perms": [
                {
                    "subsystem": "ssh",
                    "type": "SshGroup.SshNode",
                    "objid": "<objid>",
                    "action": "view",
                },
                {
                    "subsystem": "ssh",
                    "type": "SshGroup.SshNode.SshUser",
                    "objid": "<objid2>",
                    "action": "view",
                },
            ],
        },
    }

    def __init__(self, *args, **kvargs):
        """ """
        SshApiObject.__init__(self, *args, **kvargs)

        self.username = None
        self.password = None
        self.node_id = None

        if self.model is not None:
            self.username = self.model.username
            self.password = self.model.password
            self.node_id = self.model.node_id
            self.node_name = getattr(self.model, "node_name", None)
            self.key_id = getattr(self.model, "key_id", None)
            self.key_name = getattr(self.model, "key_name", None)

        # child classes
        self.child_classes = []

        self.update_object = self.manager.update_ssh_user
        self.delete_object = self.manager.delete

    def info(self):
        """Get object info

        :return: Dictionary with object info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = SshApiObject.info(self)
        info.update(
            {
                "id": str(self.oid),
                "uuid": str(self.uuid),
                "username": str(self.username),
                "password": str(self.password),
                "node_id": self.node_id,
                "node_name": self.node_name,
                "key_id": self.key_id,
                "key_name": self.key_name,
            }
        )
        return info

    def detail(self):
        """Get object extended info

        :return: Dictionary with object detail.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = self.info()
        return info

    def get_password(self):
        """Get user password not encrypted"""
        self.verify_permisssions(action="use")

        return self.decrypt_data(str(self.password))
