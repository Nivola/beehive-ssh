# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte

from base64 import b64decode
import ujson as json
from Crypto.PublicKey import RSA, DSA, ECC
from beehive_ssh.controller.object import SshApiObject


class ApiSshKey(SshApiObject):
    objdef = "SshKey"
    objuri = "gas/keys"
    objname = "sshkey"
    objdesc = "sshkey"

    role_templates = {
        "ApiSuperAdmin": {
            "desc": "Super administrator. Can all",
            "name": "ApiSuperAdminRole",
            "perms": [{"subsystem": "ssh", "type": "SshKey", "objid": "*", "action": "*"}],
        },
        "master": {
            "desc": "Key owner. Can manager key",
            "name": "KeyAdminRole",
            "perms": [
                {
                    "subsystem": "ssh",
                    "type": "SshKey",
                    "objid": "<objid>",
                    "action": "*",
                }
            ],
        },
        "viewer": {
            "desc": "Key viewer. Can list key",
            "name": "KeyViewerRole",
            "perms": [
                {
                    "subsystem": "ssh",
                    "type": "SshKey",
                    "objid": "<objid>",
                    "action": "view",
                }
            ],
        },
    }
    role_templates_exclusions = ["ApiSuperAdmin"]

    def __init__(self, *args, **kvargs):
        """ """
        SshApiObject.__init__(self, *args, **kvargs)

        self.priv_key = None
        self.pub_key = None

        if self.model is not None:
            self.priv_key = self.model.priv_key
            self.pub_key = self.model.pub_key

        # child classes
        self.child_classes = []

        self.update_object = self.manager.update_ssh_key
        self.delete_object = self.manager.delete

    def __ssh_key_info(self):
        ssh_key = b64decode(self.pub_key)
        algorithm = "GARBAGE"
        key_length = -1
        # Split the key into its components
        parts = ssh_key.split()

        # Check if it has the correct number of parts
        if len(parts) != 2:
            return algorithm, key_length

        # Should be 'ssh-rsa', 'ssh-dss', etc.
        algorithm = parts[0].decode()

        try:
            key = None
            # Add new algorithms here
            if algorithm == "ssh-rsa":
                # Import RSA key
                key = RSA.import_key(ssh_key)
            elif algorithm == "ssh-dss":
                # Import DSA key (assuming standard DSA format)
                key = DSA.import_key(ssh_key)
            elif algorithm.startswith("ecdsa"):
                # Import ECDSA key (assuming standard ECDSA format)
                key = ECC.import_key(ssh_key)
            else:
                return algorithm, key_length
            key_length = key.n.bit_length()
        except Exception:
            return algorithm, key_length
        return algorithm, key_length

    def info(self):
        """Get object info

        :return: Dictionary with object info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = SshApiObject.info(self)
        key_type, key_bits = self.__ssh_key_info()
        info.update(
            {
                "name": str(self.name),
                "priv_key": self.priv_key,
                "pub_key": self.pub_key,
                "type": key_type,
                "bits": key_bits,
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

    def pre_update(self, *args, **kvargs):
        """Pre update function. This function is used in update method.

        :param args: custom params
        :param kvargs: custom params
        :param kvargs.cid: container id
        :param kvargs.id: resource id
        :param kvargs.uuid: resource uuid
        :param kvargs.objid: resource objid
        :param kvargs.ext_id: resource remote id
        :param kvargs.priv_key: [optional]
        :param kvargs.pub_key: [optional]
        :param kvargs.active: [optional]
        :param kvargs.openstack_key: [optional]
        :return: kvargs
        :raise ApiManagerError:
        """
        openstack_key = kvargs.pop("openstack_key", None)
        if openstack_key is not None:
            kvargs["attribute"] = json.dumps({"openstack_name": openstack_key})

        return kvargs
