# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte

from beehive.module.basic.views.status import StatusAPI
from beehive.common.apimanager import ApiModule
from beecell.simple import get_class_name
from beehive_ssh.controller import SshController
from beehive_ssh.views.ssh_ansible import SshAnsibleAPI
from beehive_ssh.views.ssh_group import SshGroupAPI
from beehive_ssh.views.ssh_node import SshNodeAPI
from beehive_ssh.views.ssh_user import SshUserAPI
from beehive_ssh.views.ssh_key import SshKeyAPI


class SshModule(ApiModule):
    def __init__(self, api_manager):
        self.name = "SshModule"
        self.base_path = "gas"

        ApiModule.__init__(self, api_manager, self.name)

        self.apis = [
            StatusAPI,
            SshGroupAPI,
            SshNodeAPI,
            SshUserAPI,
            SshKeyAPI,
            SshAnsibleAPI,
        ]
        self.api_plugins = {}
        self.controller = SshController(self)

    def get_controller(self):
        return self.controller

    def set_apis(self, apis):
        self.apis.extend(apis)
        # self.api_plugins
        for api in self.apis:
            self.logger.debug("Set apis: %s" % get_class_name(api))
