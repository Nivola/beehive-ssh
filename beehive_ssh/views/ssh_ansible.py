# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2023 CSI-Piemonte

from beehive.common.apimanager import (
    ApiView,
    ApiObjectResponseSchema,
    GetApiObjectRequestSchema,
)
from flasgger import fields, Schema
from beecell.swagger import SwaggerHelper
from beehive_ssh.views import SshApiView


class GetInventoryRequestSchema(Schema):
    group = fields.String(required=False, example="Prova", allow_none=True, description="Group id or name")
    node = fields.String(required=False, example="Prova", allow_none=True, description="Node id or name")
    node_name = fields.String(
        required=False,
        example="Prova",
        allow_none=True,
        description="Node name pattern",
    )


class GetInventoryResponseSchema(Schema):
    ansible = fields.Dict(required=True, example={})


class GetInventory(SshApiView):
    tags = ["ssh"]
    definitions = {
        "GetInventoryResponseSchema": GetInventoryResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(GetInventoryRequestSchema)
    parameters_schema = GetInventoryRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": GetInventoryResponseSchema}})

    def get(self, controller, data, *args, **kwargs):
        """
        Return a dynamic ansible inventory
        Return a dynamic ansible inventory
        """
        res = controller.get_ansible_inventory(**data)
        return {"ansible": res}


class GetInventoryNodeParamsResponseSchema(ApiObjectResponseSchema):
    ip_address = fields.String(required=True)
    node_type = fields.String(required=True)
    attribute = fields.String(required=False)


class GetInventoryNodeResponseSchema(Schema):
    ansible = fields.Nested(GetInventoryNodeParamsResponseSchema, required=True, allow_none=True)


class GetInventoryNode(SshApiView):
    tags = ["ssh"]
    definitions = {
        "GetInventoryNodeResponseSchema": GetInventoryNodeResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SshApiView.setResponses({200: {"description": "success", "schema": GetInventoryNodeResponseSchema}})

    def get(self, controller, data, node, *args, **kwargs):
        res = controller.get_ansible_inventory(node=node)
        res = res.get("_meta").get("hostvars").get(node)
        return {"ansible": res}


class SshAnsibleAPI(ApiView):
    """SshAnsibleAPI"""

    @staticmethod
    def register_api(module, **kwargs):
        base = "gas"
        rules = [
            ("%s/ansible" % base, "GET", GetInventory, {}),
            ("%s/ansible/<node>" % base, "GET", GetInventoryNode, {}),
        ]

        ApiView.register_api(module, rules, **kwargs)
