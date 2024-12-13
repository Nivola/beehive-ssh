# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte

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
from beehive_ssh.controller import SshController


class GetSshGroupsParamsResponseSchema(ApiObjectResponseSchema):
    attribute = fields.String(required=False, default="Public")


class GetSshGroupResponseSchema(Schema):
    group = fields.Nested(GetSshGroupsParamsResponseSchema, required=True, allow_none=True)


class GetSshGroup(SshApiView):
    tags = ["ssh"]
    definitions = {
        "GetSshGroupResponseSchema": GetSshGroupResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SshApiView.setResponses({200: {"description": "success", "schema": GetSshGroupResponseSchema}})

    def get(self, controller: SshController, data: dict, oid: str, *args, **kwargs):
        group = controller.get_ssh_group(oid)
        return {"group": group.detail()}


class ListSshGroupsRequestSchema(ApiObjectRequestFiltersSchema, PaginatedRequestQuerySchema):
    pass


class ListSshGroupsResponseSchema(PaginatedResponseSchema):
    groups = fields.Nested(GetSshGroupsParamsResponseSchema, many=True, required=True, allow_none=True)


class ListSshGroups(SshApiView):
    tags = ["ssh"]
    definitions = {
        "ListSshGroupsResponseSchema": ListSshGroupsResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ListSshGroupsRequestSchema)
    parameters_schema = ListSshGroupsRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": ListSshGroupsResponseSchema}})

    def get(self, controller: SshController, data: dict, *args, **kwargs):
        """
        List groups
        Call this api to list all the existing groups
        """

        groups, total = controller.get_paginated_ssh_groups(**data)
        res = [r.info() for r in groups]
        return self.format_paginated_response(res, "groups", total, **data)


class GetSshGroupPerms(SshApiView):
    tags = ["ssh"]
    definitions = {
        "ApiObjectPermsRequestSchema": ApiObjectPermsRequestSchema,
        "ApiObjectPermsResponseSchema": ApiObjectPermsResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ApiObjectPermsRequestSchema)
    parameters_schema = PaginatedRequestQuerySchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": ApiObjectPermsResponseSchema}})

    def get(self, controller: SshController, data: dict, oid: str, *args, **kwargs):
        group = controller.get_ssh_group(oid)
        res, total = group.authorization(**data)
        return self.format_paginated_response(res, "perms", total, **data)


class CreateSshGroupParamRequestSchema(ApiBaseSshObjectCreateRequestSchema):
    attribute = fields.String(required=False)


class CreateSshGroupRequestSchema(Schema):
    group = fields.Nested(CreateSshGroupParamRequestSchema, context="body")


class CreateSshGroupBodyRequestSchema(Schema):
    body = fields.Nested(CreateSshGroupRequestSchema, context="body")


class CreateSshGroup(SshApiView):
    tags = ["ssh"]
    definitions = {
        "CreateSshGroupRequestSchema": CreateSshGroupRequestSchema,
        "CrudApiObjectResponseSchema": CrudApiObjectResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(CreateSshGroupBodyRequestSchema)
    parameters_schema = CreateSshGroupRequestSchema
    responses = SshApiView.setResponses({201: {"description": "success", "schema": CrudApiObjectResponseSchema}})

    def post(self, controller: SshController, data: dict, *args, **kwargs):
        self.logger.warning(data)
        resp = controller.add_ssh_group(**data.get("group"))
        return ({"uuid": resp}, 201)


class UpdateSshGroupParamRequestSchema(Schema):
    name = fields.String(required=False)
    desc = fields.String(required=False)
    active = fields.Boolean(required=False)
    attribute = fields.String(required=False)


class UpdateSshGroupRequestSchema(Schema):
    group = fields.Nested(UpdateSshGroupParamRequestSchema)


class UpdateSshGroupBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(UpdateSshGroupRequestSchema, context="body")


class UpdateSshGroup(SshApiView):
    tags = ["ssh"]
    definitions = {
        "UpdateSshGroupRequestSchema": UpdateSshGroupRequestSchema,
        "CrudApiObjectResponseSchema": CrudApiObjectResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(UpdateSshGroupBodyRequestSchema)
    parameters_schema = UpdateSshGroupRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": CrudApiObjectResponseSchema}})

    def put(self, controller: SshController, data: dict, oid: str, *args, **kwargs):
        group = controller.get_ssh_group(oid)
        data = data.get("group")
        resp = group.update(**data)
        return ({"uuid": resp}, 200)


class DeleteSshGroup(SshApiView):
    tags = ["ssh"]
    definitions = {}
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SshApiView.setResponses({204: {"description": "no response"}})

    def delete(self, controller: SshController, data: dict, oid: str, *args, **kwargs):
        group = controller.get_ssh_group(oid)
        resp = group.delete(soft=True)
        # resp = controller.delete_group(group.model)
        return (resp, 204)


class AddSshGroupNodeRequestSchema(Schema):
    node = fields.String(required=True, description="Node name, id or uuid")


class AddSshGroupNodeBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(AddSshGroupNodeRequestSchema, context="body")


class AddSshGroupNode(SshApiView):
    tags = ["ssh"]
    definitions = {
        "AddSshGroupNodeRequestSchema": AddSshGroupNodeRequestSchema,
        "CrudApiObjectResponseSchema": CrudApiObjectResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(AddSshGroupNodeBodyRequestSchema)
    parameters_schema = AddSshGroupNodeRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": CrudApiObjectResponseSchema}})

    def put(self, controller: SshController, data: dict, oid: str, *args, **kwargs):
        group = controller.get_ssh_group(oid)
        node = data.get("node")
        resp = group.add_node(node)
        return {"uuid": resp}, 200


class DeleteSshGroupNodeRequestSchema(Schema):
    node = fields.String(required=True, description="Node name, id or uuid")


class DeleteSshGroupNodeBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(DeleteSshGroupNodeRequestSchema, context="body")


class DeleteSshGroupNode(SshApiView):
    tags = ["ssh"]
    definitions = {
        "DeleteSshGroupNodeRequestSchema": DeleteSshGroupNodeRequestSchema,
        "CrudApiObjectResponseSchema": CrudApiObjectResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(DeleteSshGroupNodeBodyRequestSchema)
    parameters_schema = DeleteSshGroupNodeRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": CrudApiObjectResponseSchema}})

    def delete(self, controller: SshController, data: dict, oid: str, *args, **kwargs):
        group = controller.get_ssh_group(oid)
        node = data.get("node")
        resp = group.remove_node(node)
        return {"uuid": resp}, 200


class GetGroupRolesItemResponseSchema(ApiObjectResponseSchema):
    name = fields.String(required=True, default="master")
    desc = fields.String(required=True, default="")


class GetGroupRolesResponseSchema(Schema):
    roles = fields.Nested(GetGroupRolesItemResponseSchema, required=True, allow_none=True)


class GetGroupRoles(SshApiView):
    tags = ["authority"]
    definitions = {
        "GetGroupRolesResponseSchema": GetGroupRolesResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ApiObjectPermsRequestSchema)
    parameters_schema = ApiObjectPermsRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": ApiObjectPermsResponseSchema}})

    def get(self, controller: str, data: dict, oid: str, *args, **kwargs):
        """
        List group object permission
        Call this api to list object permissions
        """
        group = controller.get_ssh_group(oid)
        res = group.get_role_templates()
        return {"roles": res, "count": len(res)}


class GetGroupUsersItemResponseSchema(ApiObjectResponseSchema):
    role = fields.String(required=True, default="master")


class GetGroupUsersResponseSchema(Schema):
    users = fields.Nested(GetGroupUsersItemResponseSchema, required=True, allow_none=True)


class GetGroupUsers(SshApiView):
    tags = ["authority"]
    definitions = {
        "GetGroupUsersResponseSchema": GetGroupUsersResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ApiObjectPermsRequestSchema)
    parameters_schema = ApiObjectPermsRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": ApiObjectPermsResponseSchema}})

    def get(self, controller: SshController, data: dict, oid: str, *args, **kwargs):
        """
        List group object permission
        Call this api to list object permissions
        """
        group = controller.get_ssh_group(oid)
        res = group.get_users()
        return {"users": res, "count": len(res)}


class SetGroupUsersParamRequestSchema(Schema):
    user_id = fields.String(required=False, default="prova", description="User name, id or uuid")
    role = fields.String(required=False, default="prova", description="Role name, id or uuid")


class SetGroupUsersRequestSchema(Schema):
    user = fields.Nested(SetGroupUsersParamRequestSchema)


class SetGroupUsersBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(SetGroupUsersRequestSchema, context="body")


class SetGroupUsers(SshApiView):
    tags = ["authority"]
    definitions = {
        "SetGroupUsersRequestSchema": SetGroupUsersRequestSchema,
        "CrudApiObjectSimpleResponseSchema": CrudApiObjectSimpleResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(SetGroupUsersBodyRequestSchema)
    parameters_schema = SetGroupUsersRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": CrudApiObjectSimpleResponseSchema}})

    def post(self, controller: SshController, data, oid, *args, **kwargs):
        """
        Set group user
        Set group user
        """
        group = controller.get_ssh_group(oid)
        data = data.get("user")
        resp = group.set_user(**data)
        return True, 200


class UnsetGroupUsersParamRequestSchema(Schema):
    user_id = fields.String(required=False, default="prova", description="User name, id or uuid")
    role = fields.String(required=False, default="prova", description="Role name, id or uuid")


class UnsetGroupUsersRequestSchema(Schema):
    user = fields.Nested(UnsetGroupUsersParamRequestSchema)


class UnsetGroupUsersBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(UnsetGroupUsersRequestSchema, context="body")


class UnsetGroupUsers(SshApiView):
    tags = ["authority"]
    definitions = {
        "UnsetGroupUsersRequestSchema": UnsetGroupUsersRequestSchema,
        "CrudApiObjectSimpleResponseSchema": CrudApiObjectSimpleResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(UnsetGroupUsersBodyRequestSchema)
    parameters_schema = UnsetGroupUsersRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": CrudApiObjectSimpleResponseSchema}})

    def delete(self, controller, data, oid, *args, **kwargs):
        """
        Unset group user
        Unset group user
        """
        group = controller.get_ssh_group(oid)
        data = data.get("user")
        resp = group.unset_user(**data)
        return True, 200


class GetGroupGroupsItemResponseSchema(ApiObjectResponseSchema):
    role = fields.String(required=True, default="master")


class GetGroupGroupsResponseSchema(Schema):
    groups = fields.Nested(GetGroupGroupsItemResponseSchema, required=True, allow_none=True)


class GetGroupGroups(SshApiView):
    tags = ["authority"]
    definitions = {
        "GetGroupGroupsResponseSchema": GetGroupGroupsResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ApiObjectPermsRequestSchema)
    parameters_schema = ApiObjectPermsRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": ApiObjectPermsResponseSchema}})

    def get(self, controller: SshController, data, oid, *args, **kwargs):
        """
        List group object permission
        Call this api to list object permissions
        """
        from beehive_ssh.controller import ApiSshGroup

        group: ApiSshGroup = controller.get_ssh_group(oid)
        res = group.get_groups()
        return {"groups": res, "count": len(res)}


class SetGroupGroupsParamRequestSchema(Schema):
    group_id = fields.String(required=False, default="prova", description="Group name, id or uuid")
    role = fields.String(required=False, default="prova", description="Role name, id or uuid")


class SetGroupGroupsRequestSchema(Schema):
    group = fields.Nested(SetGroupGroupsParamRequestSchema)


class SetGroupGroupsBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(SetGroupGroupsRequestSchema, context="body")


class SetGroupGroups(SshApiView):
    tags = ["authority"]
    definitions = {
        "SetGroupGroupsRequestSchema": SetGroupGroupsRequestSchema,
        "CrudApiObjectSimpleResponseSchema": CrudApiObjectSimpleResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(SetGroupGroupsBodyRequestSchema)
    parameters_schema = SetGroupGroupsRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": CrudApiObjectSimpleResponseSchema}})

    def post(self, controller: SshController, data, oid, *args, **kwargs):
        """
        Set group group
        Set group group
        """
        from beehive_ssh.controller import ApiSshGroup

        group: ApiSshGroup = controller.get_ssh_group(oid)
        data = data.get("group")
        resp = group.set_group(**data)
        return True, 200


class UnsetGroupGroupsParamRequestSchema(Schema):
    group_id = fields.String(required=False, default="prova", description="Group name, id or uuid")
    role = fields.String(required=False, default="prova", description="Role name, id or uuid")


class UnsetGroupGroupsRequestSchema(Schema):
    group = fields.Nested(UnsetGroupGroupsParamRequestSchema)


class UnsetGroupGroupsBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(UnsetGroupGroupsRequestSchema, context="body")


class UnsetGroupGroups(SshApiView):
    tags = ["authority"]
    definitions = {
        "UnsetGroupGroupsRequestSchema": UnsetGroupGroupsRequestSchema,
        "CrudApiObjectSimpleResponseSchema": CrudApiObjectSimpleResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(UnsetGroupGroupsBodyRequestSchema)
    parameters_schema = UnsetGroupGroupsRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": CrudApiObjectSimpleResponseSchema}})

    def delete(self, controller: SshController, data, oid, *args, **kwargs):
        """
        Unset group group
        Unset group group
        """
        group = controller.get_ssh_group(oid)
        data = data.get("group")
        resp = group.unset_group(**data)
        return True, 200


class SshGroupAPI(ApiView):
    """SshGroupAPI"""

    @staticmethod
    def register_api(module, **kwargs):
        base = "gas"
        rules = [
            ("%s/groups" % base, "GET", ListSshGroups, {}),
            ("%s/groups/<oid>" % base, "GET", GetSshGroup, {}),
            ("%s/groups" % base, "POST", CreateSshGroup, {}),
            ("%s/groups/<oid>" % base, "PUT", UpdateSshGroup, {}),
            ("%s/groups/<oid>" % base, "DELETE", DeleteSshGroup, {}),
            ("%s/groups/<oid>/node" % base, "PUT", AddSshGroupNode, {}),
            ("%s/groups/<oid>/node" % base, "DELETE", DeleteSshGroupNode, {}),
            ("%s/groups/<oid>/perms" % base, "GET", GetSshGroupPerms, {}),
            ("%s/groups/<oid>/roles" % base, "GET", GetGroupRoles, {}),
            ("%s/groups/<oid>/users" % base, "GET", GetGroupUsers, {}),
            ("%s/groups/<oid>/users" % base, "POST", SetGroupUsers, {}),
            ("%s/groups/<oid>/users" % base, "DELETE", UnsetGroupUsers, {}),
            ("%s/groups/<oid>/groups" % base, "GET", GetGroupGroups, {}),
            ("%s/groups/<oid>/groups" % base, "POST", SetGroupGroups, {}),
            ("%s/groups/<oid>/groups" % base, "DELETE", UnsetGroupGroups, {}),
        ]

        ApiView.register_api(module, rules, **kwargs)
