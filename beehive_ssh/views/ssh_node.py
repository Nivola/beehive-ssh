# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2023 CSI-Piemonte

from marshmallow.validate import OneOf

from beehive.common.apimanager import (
    ApiView,
    PaginatedRequestQuerySchema,
    PaginatedResponseSchema,
    ApiObjectResponseSchema,
    CrudApiObjectResponseSchema,
    GetApiObjectRequestSchema,
    ApiObjectPermsResponseSchema,
    ApiObjectPermsRequestSchema,
    ApiObjectRequestFiltersSchema,
    CrudApiObjectSimpleResponseSchema,
)
from flasgger import fields, Schema
from beecell.swagger import SwaggerHelper
from beehive_ssh.views import SshApiView, ApiBaseSshObjectCreateRequestSchema


class ListSshNodesRequestSchema(ApiObjectRequestFiltersSchema, PaginatedRequestQuerySchema):
    group_id = fields.String(required=False, context="query")
    key_id = fields.String(required=False, context="query")
    ip_address = fields.String(required=False, context="query")
    names = fields.String(required=False, context="query")


class ListSshNodesParamsResponseSchema(ApiObjectResponseSchema):
    ip_address = fields.String(required=True)
    node_type = fields.String(required=True)
    attribute = fields.String(required=False)
    password = fields.String(required=False)


class ListSshNodesResponseSchema(PaginatedResponseSchema):
    nodes = fields.Nested(ListSshNodesParamsResponseSchema, many=True, required=True, allow_none=True)


class ListSshNodes(SshApiView):
    tags = ["ssh"]
    definitions = {
        "ListSshNodesResponseSchema": ListSshNodesResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ListSshNodesRequestSchema)
    parameters_schema = ListSshNodesRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": ListSshNodesResponseSchema}})

    def get(self, controller, data, *args, **kwargs):
        """
        List nodes
        Call this api to list all the existing nodes
        """
        nodes, total = controller.get_ssh_nodes(**data)
        res = [r.info() for r in nodes]
        return self.format_paginated_response(res, "nodes", total, **data)


class GetSshNodeParamsResponseSchema(ApiObjectResponseSchema):
    ip_address = fields.String(required=True)
    node_type = fields.String(required=True)
    attribute = fields.String(required=False)


class GetSshNodeResponseSchema(Schema):
    node = fields.Nested(GetSshNodeParamsResponseSchema, required=True, allow_none=True)


class GetSshNode(SshApiView):
    tags = ["ssh"]
    definitions = {
        "GetSshNodeResponseSchema": GetSshNodeResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SshApiView.setResponses({200: {"description": "success", "schema": GetSshNodeResponseSchema}})

    def get(self, controller, data, oid, *args, **kwargs):
        node = controller.get_ssh_node(oid)
        return {"node": node.detail()}


class GetSshNodePerms(SshApiView):
    tags = ["ssh"]
    definitions = {
        "ApiObjectPermsRequestSchema": ApiObjectPermsRequestSchema,
        "ApiObjectPermsResponseSchema": ApiObjectPermsResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ApiObjectPermsRequestSchema)
    parameters_schema = PaginatedRequestQuerySchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": ApiObjectPermsResponseSchema}})

    def get(self, controller, data, oid, *args, **kwargs):
        node = controller.get_ssh_node(oid)
        res, total = node.authorization(**data)
        return self.format_paginated_response(res, "perms", total, **data)


class CreateSshNodeParamRequestSchema(ApiBaseSshObjectCreateRequestSchema):
    ip_address = fields.String(required=True)
    node_type = fields.String(required=True)
    attribute = fields.String(required=False)
    group_id = fields.String(required=True)


class CreateSshNodeRequestSchema(Schema):
    node = fields.Nested(CreateSshNodeParamRequestSchema, context="body")


class CreateSshNodeBodyRequestSchema(Schema):
    body = fields.Nested(CreateSshNodeRequestSchema, context="body")


class CreateSshNode(SshApiView):
    tags = ["ssh"]
    definitions = {
        "CreateSshNodeRequestSchema": CreateSshNodeRequestSchema,
        "CrudApiObjectResponseSchema": CrudApiObjectResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(CreateSshNodeBodyRequestSchema)
    parameters_schema = CreateSshNodeRequestSchema
    responses = SshApiView.setResponses({201: {"description": "success", "schema": CrudApiObjectResponseSchema}})

    def post(self, controller, data, *args, **kwargs):
        resp = controller.add_ssh_node(**data.get("node"))
        return {"uuid": resp}, 201


class UpdateSshNodeParamRequestSchema(Schema):
    name = fields.String(required=False)
    desc = fields.String(required=False)
    active = fields.Boolean(required=False, default=False)
    ip_address = fields.String(required=False)
    node_type = fields.String(required=False)
    attribute = fields.String(required=False)


class UpdateSshNodeRequestSchema(Schema):
    node = fields.Nested(UpdateSshNodeParamRequestSchema)


class UpdateSshNodeBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(UpdateSshNodeRequestSchema, context="body")


class UpdateSshNode(SshApiView):
    tags = ["ssh"]
    definitions = {
        "UpdateSshNodeRequestSchema": UpdateSshNodeRequestSchema,
        "CrudApiObjectResponseSchema": CrudApiObjectResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(UpdateSshNodeBodyRequestSchema)
    parameters_schema = UpdateSshNodeRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": CrudApiObjectResponseSchema}})

    def put(self, controller, data, oid, *args, **kwargs):
        node = controller.get_ssh_node(oid)
        data = data.get("node")
        resp = node.update(**data)
        return {"uuid": resp}, 200


class DeleteSshNode(SshApiView):
    tags = ["ssh"]
    definitions = {}
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SshApiView.setResponses({204: {"description": "no response"}})

    def delete(self, controller, data, oid, *args, **kwargs):
        node = controller.get_ssh_node(oid)
        resp = node.delete(soft=True)
        return resp, 204


class ApiObjectActionRequestSchema(Schema):
    action = fields.String(required=True)
    action_id = fields.String(required=False)
    status = fields.String(required=False, missing=None)
    params = fields.Dict(default={}, required=True)


class ApiObjectActionBodyRequestSchema(Schema):
    body = fields.Nested(ApiObjectActionRequestSchema, context="body")


class ApiObjectActionResponseSchema(Schema):
    action = fields.String(required=True)
    action_id = fields.String(required=True)


class PutSshNodeAction(SshApiView):
    tags = ["ssh"]
    definitions = {
        "ApiObjectActionRequestSchema": ApiObjectActionRequestSchema,
        "ApiObjectActionResponseSchema": ApiObjectActionResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ApiObjectActionBodyRequestSchema)
    parameters_schema = ApiObjectActionRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": ApiObjectActionResponseSchema}})

    def put(self, controller, data, oid, *args, **kwargs):
        action = data.get("action")
        action_id = data.get("action_id", None)
        params = data.get("params")
        status = data.get("status")
        node = controller.get_ssh_node(oid)
        action_id = node.action(action, action_id, params, status=status)
        return {"action": action, "action_id": action_id}, 200


class GetSshNodeActionParamsResponseSchema(PaginatedResponseSchema):
    id = fields.Integer(required=True, example=10, description="Cmp user that made action")
    date = fields.DateTime(required=True, example="1990-12-31T23:59:59Z", description="Action time")
    user_id = fields.Dict(
        required=True,
        example={
            "ip": "pc160234.csi.it",
            "user": "admin@local",
            "identity": "a4a86567-20c0-4160-9081-f227bfbdc82c",
        },
        description="Cmp user that made action",
    )
    action_id = fields.String(required=True, example="test", description="Action id")
    action = fields.String(required=True, example="test", description="Action name")
    elapsed = fields.String(required=True, example="test", description="Action elapsed time")
    node_id = fields.String(required=True, example="test", description="Node id")
    node_name = fields.String(required=True, example="test", description="Node name")
    node_user = fields.Dict(
        required=True,
        example={"name": "root", "key": "19aa137b-3b3e-479c-9030-798325ddee70"},
        description="Node user",
    )
    status = fields.String(required=True, example="OK", description="Action status")


class GetSshNodeActionResponseSchema(Schema):
    actions = fields.Nested(GetSshNodeActionParamsResponseSchema, required=True, allow_none=True)


class GetSshNodeActionRequestSchema(PaginatedRequestQuerySchema, GetApiObjectRequestSchema):
    date = fields.String(default="1985.04.12", context="query", description="query date")


class GetSshNodeAction(SshApiView):
    tags = ["ssh"]
    definitions = {
        "GetSshNodeActionResponseSchema": GetSshNodeActionResponseSchema,
        "GetSshNodeActionRequestSchema": GetSshNodeActionRequestSchema,
    }
    parameters = SwaggerHelper().get_parameters(GetSshNodeActionRequestSchema)
    parameters_schema = GetSshNodeActionRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": GetSshNodeActionResponseSchema}})

    def get(self, controller, data, oid, *args, **kwargs):
        accesses, total = controller.get_ssh_node_actions(node_id=oid, **data)
        return self.format_paginated_response(accesses, "actions", total, **data)


class GetNodeRolesItemResponseSchema(ApiObjectResponseSchema):
    name = fields.String(required=True, default="master")
    desc = fields.String(required=True, default="")


class GetNodeRolesResponseSchema(Schema):
    roles = fields.Nested(GetNodeRolesItemResponseSchema, required=True, allow_none=True)


class GetNodeRoles(SshApiView):
    tags = ["authority"]
    definitions = {
        "GetNodeRolesResponseSchema": GetNodeRolesResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ApiObjectPermsRequestSchema)
    parameters_schema = ApiObjectPermsRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": ApiObjectPermsResponseSchema}})

    def get(self, controller, data, oid, *args, **kwargs):
        """
        List node object permission
        Call this api to list object permissions
        """
        node = controller.get_ssh_node(oid)
        res = node.get_role_templates()
        return {"roles": res, "count": len(res)}


class GetNodeUsersItemResponseSchema(ApiObjectResponseSchema):
    role = fields.String(required=True, default="master")


class GetNodeUsersResponseSchema(Schema):
    users = fields.Nested(GetNodeUsersItemResponseSchema, required=True, allow_none=True)


class GetNodeUsers(SshApiView):
    tags = ["authority"]
    definitions = {
        "GetNodeUsersResponseSchema": GetNodeUsersResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ApiObjectPermsRequestSchema)
    parameters_schema = ApiObjectPermsRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": ApiObjectPermsResponseSchema}})

    def get(self, controller, data, oid, *args, **kwargs):
        """
        List node object permission
        Call this api to list object permissions
        """
        node = controller.get_ssh_node(oid)
        res = node.get_users()
        return {"users": res, "count": len(res)}


class SetNodeUsersParamRequestSchema(Schema):
    user_id = fields.String(required=False, default="prova", description="User name, id or uuid")
    role = fields.String(required=False, default="prova", description="Role name, id or uuid")


class SetNodeUsersRequestSchema(Schema):
    user = fields.Nested(SetNodeUsersParamRequestSchema)


class SetNodeUsersBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(SetNodeUsersRequestSchema, context="body")


class SetNodeUsers(SshApiView):
    tags = ["authority"]
    definitions = {
        "SetNodeUsersRequestSchema": SetNodeUsersRequestSchema,
        "CrudApiObjectSimpleResponseSchema": CrudApiObjectSimpleResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(SetNodeUsersBodyRequestSchema)
    parameters_schema = SetNodeUsersRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": CrudApiObjectSimpleResponseSchema}})

    def post(self, controller, data, oid, *args, **kwargs):
        """
        Set node user
        Set node user
        """
        node = controller.get_ssh_node(oid)
        data = data.get("user")
        resp = node.set_user(**data)
        return True, 200


class UnsetNodeUsersParamRequestSchema(Schema):
    user_id = fields.String(required=False, default="prova", description="User name, id or uuid")
    role = fields.String(required=False, default="prova", description="Role name, id or uuid")


class UnsetNodeUsersRequestSchema(Schema):
    user = fields.Nested(UnsetNodeUsersParamRequestSchema)


class UnsetNodeUsersBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(UnsetNodeUsersRequestSchema, context="body")


class UnsetNodeUsers(SshApiView):
    tags = ["authority"]
    definitions = {
        "UnsetNodeUsersRequestSchema": UnsetNodeUsersRequestSchema,
        "CrudApiObjectSimpleResponseSchema": CrudApiObjectSimpleResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(UnsetNodeUsersBodyRequestSchema)
    parameters_schema = UnsetNodeUsersRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": CrudApiObjectSimpleResponseSchema}})

    def delete(self, controller, data, oid, *args, **kwargs):
        """
        Unset node user
        Unset node user
        """
        node = controller.get_ssh_node(oid)
        data = data.get("user")
        resp = node.unset_user(**data)
        return True, 200


class GetNodeGroupsItemResponseSchema(ApiObjectResponseSchema):
    role = fields.String(required=True, default="master")


class GetNodeGroupsResponseSchema(Schema):
    groups = fields.Nested(GetNodeGroupsItemResponseSchema, required=True, allow_none=True)


class GetNodeGroups(SshApiView):
    tags = ["authority"]
    definitions = {
        "GetNodeGroupsResponseSchema": GetNodeGroupsResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ApiObjectPermsRequestSchema)
    parameters_schema = ApiObjectPermsRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": ApiObjectPermsResponseSchema}})

    def get(self, controller, data, oid, *args, **kwargs):
        """
        List group object permission
        Call this api to list object permissions
        """
        group = controller.get_ssh_node(oid)
        res = group.get_groups()
        return {"groups": res, "count": len(res)}


class SetNodeGroupsParamRequestSchema(Schema):
    group_id = fields.String(required=False, default="prova", description="Node name, id or uuid")
    role = fields.String(required=False, default="prova", description="Role name, id or uuid")


class SetNodeGroupsRequestSchema(Schema):
    group = fields.Nested(SetNodeGroupsParamRequestSchema)


class SetNodeGroupsBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(SetNodeGroupsRequestSchema, context="body")


class SetNodeGroups(SshApiView):
    tags = ["authority"]
    definitions = {
        "SetNodeGroupsRequestSchema": SetNodeGroupsRequestSchema,
        "CrudApiObjectSimpleResponseSchema": CrudApiObjectSimpleResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(SetNodeGroupsBodyRequestSchema)
    parameters_schema = SetNodeGroupsRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": CrudApiObjectSimpleResponseSchema}})

    def post(self, controller, data, oid, *args, **kwargs):
        """
        Set group group
        Set group group
        """
        group = controller.get_ssh_node(oid)
        data = data.get("group")
        resp = group.set_group(**data)
        return True, 200


class UnsetNodeGroupsParamRequestSchema(Schema):
    group_id = fields.String(required=False, default="prova", description="Group name, id or uuid")
    role = fields.String(required=False, default="prova", description="Role name, id or uuid")


class UnsetNodeGroupsRequestSchema(Schema):
    group = fields.Nested(UnsetNodeGroupsParamRequestSchema)


class UnsetNodeGroupsBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(UnsetNodeGroupsRequestSchema, context="body")


class UnsetNodeGroups(SshApiView):
    tags = ["authority"]
    definitions = {
        "UnsetNodeGroupsRequestSchema": UnsetNodeGroupsRequestSchema,
        "CrudApiObjectSimpleResponseSchema": CrudApiObjectSimpleResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(UnsetNodeGroupsBodyRequestSchema)
    parameters_schema = UnsetNodeGroupsRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": CrudApiObjectSimpleResponseSchema}})

    def delete(self, controller, data, oid, *args, **kwargs):
        """
        Unset group group
        Unset group group
        """
        group = controller.get_ssh_node(oid)
        data = data.get("group")
        resp = group.unset_group(**data)
        return True, 200


class SshNodeAPI(ApiView):
    """SshNodeAPI"""

    @staticmethod
    def register_api(module, **kwargs):
        base = "gas"
        rules = [
            ("%s/nodes" % base, "GET", ListSshNodes, {}),
            ("%s/nodes/<oid>" % base, "GET", GetSshNode, {}),
            ("%s/nodes" % base, "POST", CreateSshNode, {}),
            ("%s/nodes/<oid>" % base, "PUT", UpdateSshNode, {}),
            ("%s/nodes/<oid>" % base, "DELETE", DeleteSshNode, {}),
            ("%s/nodes/<oid>/action" % base, "PUT", PutSshNodeAction, {}),
            ("%s/nodes/<oid>/actions" % base, "GET", GetSshNodeAction, {}),
            ("%s/nodes/<oid>/perms" % base, "GET", GetSshNodePerms, {}),
            ("%s/nodes/<oid>/roles" % base, "GET", GetNodeRoles, {}),
            ("%s/nodes/<oid>/users" % base, "GET", GetNodeUsers, {}),
            ("%s/nodes/<oid>/users" % base, "POST", SetNodeUsers, {}),
            ("%s/nodes/<oid>/users" % base, "DELETE", UnsetNodeUsers, {}),
            ("%s/nodes/<oid>/groups" % base, "GET", GetNodeGroups, {}),
            ("%s/nodes/<oid>/groups" % base, "POST", SetNodeGroups, {}),
            ("%s/nodes/<oid>/groups" % base, "DELETE", UnsetNodeGroups, {}),
        ]

        ApiView.register_api(module, rules, **kwargs)
