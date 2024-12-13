# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte

from copy import deepcopy
from typing import List

# from base64 import b64encode
# from six.moves.urllib.parse import urlencode
# from six import StringIO, ensure_binary
import ujson as json
from typing import List
from beehive.common.apiclient import BeehiveApiClientError
from beehive.common.apimanager import ApiObject, ApiManagerError

# from beehive.common.event import Event
# from beehive.common.data import trace, TransactionError, operation
from beecell.types.type_dict import dict_get
from beecell.types.type_id import id_gen
from beecell.types.type_string import truncate

# from paramiko import DSSKey, ECDSAKey, RSAKey
# from paramiko.ssh_exception import SSHException
from beehive_ssh.dao.SshDao import SshDbManager

# from beehive_ssh.model import SshGroup, SshNode, SshUser, SshKey


class SshApiObject(ApiObject):
    module = "SshModule"
    objtype = "ssh"

    SSH_OPERATION = "SSH"

    manager = SshDbManager()

    role_templates = {}

    role_templates_exclusions = []

    def __init__(self, *args, **kvargs):
        """ """
        ApiObject.__init__(self, *args, **kvargs)

        self.version = None
        self.attribs = None
        from beehive_ssh.controller.controller import SshController

        self.controller: SshController
        self.manager: SshDbManager
        if self.model is not None:
            self.version = getattr(self.model, "version", "1.0")
        self.set_attribs()

    def set_attribs(self):
        """Set attributes

        :param attributes: attributes
        """
        self.attribs = {}
        if self.model is not None and self.model.attribute is not None:
            try:
                self.attribs = json.loads(self.model.attribute)
            except Exception as ex:
                self.attribs = {}

    def get_attribs(self, key=None):
        """Get attributes

        :param key: key to search in attributes dict [optional]
        :return: attributes value
        """
        res = self.attribs
        if key is not None:
            res = dict_get(res, key)

        return res

    def info(self):
        """Get object info

        :return: Dictionary with object info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = ApiObject.info(self)
        info.update({"version": self.version, "attributes": self.attribs})
        return info

    def post_delete(self, *args, **kvargs):
        """Post delete function. This function is used in delete method. Extend
        this function to execute action after object was deleted.

        :param args: custom params
        :param kvargs: custom params
        :return: True
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        if self.update_object is not None:
            name = "%s-%s-DELETED" % (self.name, id_gen())
            self.update_object(oid=self.oid, name=name)
            self.logger.debug("Update name of %s to %s", self.uuid, name)
        return True

    #
    # authorization
    #
    def get_role_templates(self) -> List[dict]:
        """get role template for class instances

        Returns:
            List[dict]: a list of role templates
        """
        res = []
        for k, v in self.role_templates.items():
            res.append({"name": k, "desc": v.get("desc")})
        return res

    def get_role_template_names(self):
        res = []
        for k, v in self.role_templates.items():
            res.append(k)

        for item in self.role_templates_exclusions:
            res.remove(item)

        return res

    def get_users(self):
        res = []
        try:
            self.verify_permisssions("update")

            # get users
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
        except BeehiveApiClientError:
            self.logger.error("Error get %s %s users" % (self.objname, self.name), exc_info=1)
            raise ApiManagerError("Error get %s %s users" % (self.objname, self.name))
        self.logger.debug("Get %s %s users: %s" % (self.objname, self.name, truncate(users)))
        return res

    def set_user(self, user_id=None, role=None):
        try:
            self.verify_permisssions("update")

            if role not in self.get_role_template_names():
                raise ApiManagerError("Role %s not found or can not be used" % role)

            # get perms
            role = self.role_templates.get(role)
            perms = []
            for op in role.get("perms"):
                p = deepcopy(op)
                p["objid"] = p["objid"].replace("<objid>", self.objid)
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

            # get perms
            role = self.role_templates.get(role)
            perms = []
            for op in role.get("perms"):
                p = deepcopy(op)
                p["objid"] = p["objid"].replace("<objid>", self.objid)
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
                self.logger.warn(perms)
                groups = self.api_client.get_perms_groups(perms)
                for group in groups:
                    group["role"] = tmpl
                    res.append(group)
        except BeehiveApiClientError:
            self.logger.error("Error get %s %s groups" % (self.objname, self.name), exc_info=1)
            raise ApiManagerError("Ssh error get %s %s groups" % (self.objname, self.name))
        self.logger.debug("Get %s %s groups: %s" % (self.objname, self.name, truncate(groups)))
        return res

    def set_group(self, group_id=None, role=None):
        try:
            self.verify_permisssions("update")

            if role not in self.get_role_template_names():
                raise ApiManagerError("Ssh role %s not found or can not be used" % role)

            # get perms
            role = self.role_templates.get(role)
            perms = []
            for op in role.get("perms"):
                p = deepcopy(op)
                p["objid"] = p["objid"].replace("<objid>", self.objid)
                perms.append(p)

            res = self.api_client.append_group_permissions(group_id, perms)
        except BeehiveApiClientError:
            self.logger.error("Error set %s %s groups" % (self.objname, self.name), exc_info=1)
            raise ApiManagerError("Ssh error set %s %s groups" % (self.objname, self.name))
        self.logger.debug("Set %s %s groups: %s" % (self.objname, self.name, res))
        return True

    def unset_group(self, group_id=None, role=None):
        try:
            self.verify_permisssions("update")

            if role not in self.get_role_template_names():
                raise ApiManagerError("Ssh role %s not found or can not be used" % role)

            # get perms
            role = self.role_templates.get(role)
            perms = []
            for op in role.get("perms"):
                p = deepcopy(op)
                p["objid"] = p["objid"].replace("<objid>", self.objid)
                perms.append(p)

            res = self.api_client.remove_group_permissions(group_id, perms)
        except BeehiveApiClientError:
            self.logger.error("Error unset %s %s groups" % (self.objname, self.name), exc_info=1)
            raise ApiManagerError("Ssh error unset %s %s groups" % (self.objname, self.name))
        self.logger.debug("Unset %s %s groups: %s" % (self.objname, self.name, res))
        return True
