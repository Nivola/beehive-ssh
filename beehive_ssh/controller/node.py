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


class ApiSshNode(SshApiObject):
    """
    Controller Object for Node: The target for ssh connections.

    Args:
        SshApiObject (_type_): _description_

    Raises:
        ApiManagerError: _description_

    Returns:
        _type_: _description_
    """

    from beehive_ssh.controller.group import ApiSshGroup

    objdef = ApiObject.join_typedef(ApiSshGroup.objdef, "SshNode")
    objuri = "gas/nodes"
    objname = "sshnode"
    objdesc = "sshnode"

    role_templates = {
        "ApiSuperAdmin": {
            "desc": "Super administrator. Can all",
            "name": "ApiSuperAdminRole",
            "perms": [
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
        "connect": {
            "desc": "Node connect. Can list node, can connect and execute command over node ",
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

        self.node_type = None
        self.ip_address = None

        if self.model is not None:
            self.node_type = self.model.node_type
            self.ip_address = self.model.ip_address

        # child classes
        from beehive_ssh.controller.user import ApiSshUser

        self.child_classes = [ApiSshUser]

        self.update_object = self.manager.update_ssh_node
        self.delete_object = self.manager.delete

    def info(self):
        """Get object info

        :return: Dictionary with object info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = SshApiObject.info(self)
        info.update({"node_type": str(self.node_type), "ip_address": self.ip_address})
        return info

    def detail(self):
        """Get object extended info

        :return: Dictionary with object detail.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = self.info()
        info["groups"] = []
        info["users"] = []
        if self.model is not None:
            for group in self.model.groups:
                info["groups"].append({"name": group.name, "id": group.uuid})
        users, total = self.controller.manager.get_paginated_users(
            node_id=self.oid, with_perm_tag=False, filter_expired=False
        )
        for user in users:
            info["users"].append(
                {
                    "name": user.username,
                    "id": user.uuid,
                    "pwd": user.password,
                    "key": user.key_name,
                }
            )
        return info

    def pre_delete(self, *args, **kvargs):
        """Pre delete function. This function is used in delete method. Extend
        this function to manipulate and validate delete input params.

        :param args: custom params
        :param kvargs: custom params
        :return: kvargs
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        # get node users
        # users, tot = self.controller.get_ssh_users(node_id=self.oid)
        users, tot = self.manager.get_node_users(node_id=self.oid)
        from beehive_ssh.controller.user import ApiSshUser

        for user in users:
            user = ApiSshUser(
                self.controller,
                oid=user.id,
                name=user.name,
                objid=user.objid,
                model=user,
            )
            user.delete(soft=True)

        return kvargs

    @trace(op="use")
    def action(self, action, action_id, orig_params, status=None):
        """Send node action

        :param action: action name
        :param action: action id
        :param params: action params
        :param status: action status
        :return:
        """
        self.verify_permisssions("use")

        if action_id is None:
            action_id = id_gen()

        params = deepcopy(orig_params)
        params.update({"node_id": self.uuid, "node_name": self.name})

        # send event
        if status is None:
            status = True
        else:
            status = (False, status)

        data = {
            "opid": action_id,
            "op": action,
            "api_id": operation.id,
            "args": [],
            # 'kwargs': compat(params),
            "kwargs": json.dumps(params),
            "elapsed": params.get("elapsed", 0),
            "response": [status, ""],
        }

        source = {
            "user": operation.user[0],
            "ip": operation.user[1],
            "identity": operation.user[2],
        }

        dest = {
            "ip": self.controller.module.api_manager.server_name,
            "port": self.controller.module.api_manager.http_socket,
            "objid": self.objid,
            "objtype": self.objtype,
            "objdef": self.objdef,
            "action": action,
        }

        # send event
        try:
            client = self.controller.module.api_manager.event_producer
            client.send(self.SSH_OPERATION, data, source, dest)
            self.logger.debug("Send ssh node %s action %s event: %s" % (self.uuid, action, action_id))
        except Exception as ex:
            self.logger.warning("Event can not be published. Event producer is not configured - %s" % ex)
        return action_id

    #
    # authorization
    #
    def get_role_templates(self):
        res = []
        for k, v in self.role_templates.items():
            res.append({"name": k, "desc": v.get("desc")})

        # find all node users
        node_users, tot = self.controller.get_ssh_users(node_id=self.oid, filter_expired=False)
        for node_user in node_users:
            self.logger.info(
                "+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+ node: %s, found user %s", self.objid, node_user.objid
            )
            for k, v in node_user.role_templates.items():
                name = k % node_user.username
                desc = v.get("desc") % node_user.username
                res.append({"name": name, "desc": desc})

        return res

    def get_role_template_names(self):
        res = []
        for k, v in self.role_templates.items():
            res.append(k)

        # find all node users
        node_users, tot = self.controller.get_ssh_users(node_id=self.oid, filter_expired=False)
        for node_user in node_users:
            self.logger.info(
                "+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+ node: %s, found user %s", self.objid, node_user.objid
            )
            for k, v in node_user.role_templates.items():
                name = k % node_user.username
                res.append(name)

        for item in self.role_templates_exclusions:
            res.remove(item)

        return res

    def get_users(self):
        res = []
        try:
            self.verify_permisssions("update")

            # get auth users for node
            for tmpl, role in self.role_templates.items():
                perms = []
                for op in role.get("perms"):
                    p = deepcopy(op)
                    objid = p["objid"].replace("<objid>", self.objid)
                    perms.append("%s,%s,%s,%s" % (p["subsystem"], p["type"], objid, p["action"]))
                users = self.api_client.get_perms_users(perms)
                for user in users:
                    user["role"] = tmpl
                    res.append(user)

            # auth users for node users
            node_users, tot = self.controller.get_ssh_users(node_id=self.oid, filter_expired=False)
            for node_user in node_users:
                self.logger.info(
                    "+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+ node: %s, found user %s", self.objid, node_user.objid
                )
                for tmpl, role in node_user.role_templates.items():
                    perms = []
                    for op in role.get("perms"):
                        p = deepcopy(op)
                        objid = p["objid"].replace("<objid>", self.objid).replace("<objid2>", node_user.objid)
                        perms.append("%s,%s,%s,%s" % (p["subsystem"], p["type"], objid, p["action"]))
                    users = self.api_client.get_perms_users(perms)
                    for user in users:
                        user["role"] = tmpl % node_user.username
                        res.append(user)
        except BeehiveApiClientError:
            self.logger.error("Error get %s %s users" % (self.objname, self.name), exc_info=1)
            raise ApiManagerError("Ssh error get %s %s users" % (self.objname, self.name))
        self.logger.debug("Get %s %s users: %s" % (self.objname, self.name, truncate(users)))
        return res

    def set_user(self, user_id=None, role=None):
        try:
            self.verify_permisssions("update")

            if role not in self.get_role_template_names():
                raise ApiManagerError("Ssh role %s not found or can not be used" % role)

            # get role and username
            role, username = role.split(".")

            # get node user
            node_users, tot = self.controller.get_ssh_users(node_id=self.oid, username=username, filter_expired=False)
            if tot == 0:
                raise ApiManagerError(
                    "Ssh user %s for node %s not found or you do not have privileges to see it" % (username, self.uuid)
                )
            node_user = node_users[0]
            self.logger.info(
                "+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+ node: %s, found user %s", self.objid, node_user.objid
            )

            # get perms
            role = node_user.role_templates.get(role + ".%s")
            perms = []
            for op in role.get("perms"):
                p = deepcopy(op)
                p["objid"] = p["objid"].replace("<objid>", self.objid).replace("<objid2>", node_user.objid)
                perms.append(p)

            res = self.api_client.append_user_permissions(user_id, perms)
        except BeehiveApiClientError:
            self.logger.error("Error set %s %s users" % (self.objname, self.name), exc_info=1)
            raise ApiManagerError("Ssh error set %s %s users" % (self.objname, self.name))
        self.logger.debug("Set %s %s users: %s" % (self.objname, self.name, res))
        return True

    def unset_user(self, user_id=None, role=None):
        try:
            self.verify_permisssions("update")

            if role not in self.get_role_template_names():
                raise ApiManagerError("Ssh role %s not found or can not be used" % role)

            # get role and username
            role, username = role.split(".")

            # get node user
            node_users, tot = self.controller.get_ssh_users(node_id=self.oid, username=username, filter_expired=False)
            if tot == 0:
                raise ApiManagerError(
                    "Ssh user %s for node %s not found or you do not have privileges to see it" % (username, self.uuid)
                )
            node_user = node_users[0]
            self.logger.info(
                "+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+ node: %s, found user %s", self.objid, node_user.objid
            )

            # get perms
            role = node_user.role_templates.get(role + ".%s")
            perms = []
            for op in role.get("perms"):
                p = deepcopy(op)
                p["objid"] = p["objid"].replace("<objid>", self.objid).replace("<objid2>", node_user.objid)
                perms.append(p)

            res = self.api_client.remove_user_permissions(user_id, perms)
        except BeehiveApiClientError:
            self.logger.error("Error unset %s %s users" % (self.objname, self.name), exc_info=1)
            raise ApiManagerError("Ssh error unset %s %s users" % (self.objname, self.name))
        self.logger.debug("Unset %s %s users: %s" % (self.objname, self.name, res))
        return True

    def get_groups(self):
        res = []
        try:
            self.verify_permisssions("update")

            # get groups
            for tmpl, role in self.role_templates.items():
                perms = []
                for op in role.get("perms"):
                    p = deepcopy(op)
                    objid = p["objid"].replace("<objid>", self.objid)
                    perms.append("%s,%s,%s,%s" % (p["subsystem"], p["type"], objid, p["action"]))
                groups = self.api_client.get_perms_groups(perms)
                for group in groups:
                    group["role"] = tmpl
                    res.append(group)

            # auth users for node users
            node_users, tot = self.controller.get_ssh_users(node_id=self.oid, filter_expired=False)
            for node_user in node_users:
                self.logger.info(
                    "+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+ node: %s, found user %s", self.objid, node_user.objid
                )
                for tmpl, role in node_user.role_templates.items():
                    perms = []
                    for op in role.get("perms"):
                        p = deepcopy(op)
                        objid = p["objid"].replace("<objid>", self.objid).replace("<objid2>", node_user.objid)
                        perms.append("%s,%s,%s,%s" % (p["subsystem"], p["type"], objid, p["action"]))
                    groups = self.api_client.get_perms_groups(perms)
                    for group in groups:
                        group["role"] = tmpl % node_user.username
                        res.append(group)
        except BeehiveApiClientError:
            self.logger.error("Error get %s %s groups" % (self.objname, self.name), exc_info=1)
            raise ApiManagerError("Ssh error get %s %s groups" % (self.objname, self.name))
        self.logger.debug("Get %s %s groups: %s" % (self.objname, self.name, truncate(groups)))
        return res

    def set_group(self, group_id=None, role=None):
        if role.find(".") > 0:
            try:
                self.verify_permisssions("update")

                if role not in self.get_role_template_names():
                    raise ApiManagerError("Ssh role %s not found or can not be used" % role)

                # get role and username
                role, username = role.split(".")

                # get node user
                node_users, tot = self.controller.get_ssh_users(
                    node_id=self.oid, username=username, filter_expired=False
                )
                if tot == 0:
                    raise ApiManagerError(
                        "Ssh user %s for node %s not found or you do not have privileges to see it"
                        % (username, self.uuid)
                    )
                node_user = node_users[0]

                self.logger.info(
                    "+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+ node: %s, found user %s", self.objid, node_user.objid
                )

                # get perms
                role = node_user.role_templates.get(role + ".%s")
                perms = []
                for op in role.get("perms"):
                    p = deepcopy(op)
                    p["objid"] = p["objid"].replace("<objid>", self.objid).replace("<objid2>", node_user.objid)
                    perms.append(p)

                res = self.api_client.append_group_permissions(group_id, perms)
            except BeehiveApiClientError:
                self.logger.error("Error set %s %s groups" % (self.objname, self.name), exc_info=1)
                raise ApiManagerError("Ssh error set %s %s groups" % (self.objname, self.name))
            self.logger.debug("Set %s %s groups: %s" % (self.objname, self.name, res))
        else:
            SshApiObject.set_group(self, group_id=group_id, role=role)
        return True

    def unset_group(self, group_id=None, role=None):
        try:
            self.verify_permisssions("update")

            if role not in self.get_role_template_names():
                raise ApiManagerError("Ssh role %s not found or can not be used" % role)

            # get role and username
            role, username = role.split(".")

            # get node user
            node_users, tot = self.controller.get_ssh_users(node_id=self.oid, username=username, filter_expired=False)
            if tot == 0:
                raise ApiManagerError(
                    "Ssh user %s for node %s not found or you do not have privileges to see it" % (username, self.uuid)
                )
            node_user = node_users[0]
            self.logger.info(
                "+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+|+ node: %s, found user %s", self.objid, node_user.objid
            )
            # get perms
            role = node_user.role_templates.get(role + ".%s")
            perms = []
            for op in role.get("perms"):
                p = deepcopy(op)
                p["objid"] = p["objid"].replace("<objid>", self.objid).replace("<objid2>", node_user.objid)
                perms.append(p)

            res = self.api_client.remove_group_permissions(group_id, perms)
        except BeehiveApiClientError:
            self.logger.error("Error unset %s %s groups" % (self.objname, self.name), exc_info=1)
            raise ApiManagerError("Ssh error unset %s %s groups" % (self.objname, self.name))
        self.logger.debug("Unset %s %s groups: %s" % (self.objname, self.name, res))
        return True
