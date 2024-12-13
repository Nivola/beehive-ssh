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
)
from flasgger import fields, Schema
from beecell.swagger import SwaggerHelper
from beehive_ssh.controller import SshController
from beehive_ssh.views import (
    SshApiView,
    ApiBaseSshObjectCreateRequestSchema,
    ApiBaseSshObjectUpdateRequestSchema,
)


class ListSshUsersRequestSchema(ApiObjectRequestFiltersSchema, PaginatedRequestQuerySchema):
    node_id = fields.String(required=False, context="query")
    username = fields.String(required=False, context="query")


class ListSshUsersParamsResponseSchema(ApiObjectResponseSchema):
    username = fields.String(required=True)
    password = fields.String(required=True)


class ListSshUsersResponseSchema(PaginatedResponseSchema):
    user = fields.Nested(ListSshUsersParamsResponseSchema, many=True, required=True, allow_none=True)


class ListSshUsers(SshApiView):
    tags = ["ssh"]
    definitions = {
        "ListSshUsersResponseSchema": ListSshUsersResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ListSshUsersRequestSchema)
    parameters_schema = ListSshUsersRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": ListSshUsersResponseSchema}})

    def get(self, controller: SshController, data: dict, *args, **kwargs):
        """
        List users
        Call this api to list all the existing users
        """
        users, total = controller.get_ssh_users(**data)
        res = [r.info() for r in users]
        return self.format_paginated_response(res, "users", total, **data)


class GetSshUserParamsResponseSchema(ApiObjectResponseSchema):
    username = fields.String(required=True)
    password = fields.String(required=True)


class GetSshUserResponseSchema(Schema):
    user = fields.Nested(GetSshUserParamsResponseSchema, required=True, allow_none=True)


class GetSshUser(SshApiView):
    tags = ["ssh"]
    definitions = {
        "GetSshUserResponseSchema": GetSshUserResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SshApiView.setResponses({200: {"description": "success", "schema": GetSshUserResponseSchema}})

    def get(self, controller: SshController, data: dict, oid: str, *args, **kwargs):
        user = controller.get_ssh_user(oid)
        return {"user": user.detail()}


class GetSshUserPerms(SshApiView):
    tags = ["ssh"]
    definitions = {
        "ApiObjectPermsRequestSchema": ApiObjectPermsRequestSchema,
        "ApiObjectPermsResponseSchema": ApiObjectPermsResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ApiObjectPermsRequestSchema)
    parameters_schema = PaginatedRequestQuerySchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": ApiObjectPermsResponseSchema}})

    def get(self, controller: SshController, data: dict, oid: str, *args, **kwargs):
        user = controller.get_ssh_user(oid)
        res, total = user.authorization(**data)
        return self.format_paginated_response(res, "perms", total, **data)


class ApiObjectPermsResponseSchema(Schema):
    password = fields.String(required=True, default="mypass", example="mypass", description="USer password")


class GetSshUserPwd(SshApiView):
    tags = ["ssh"]
    definitions = {
        "GetApiObjectRequestSchema": GetApiObjectRequestSchema,
        "ApiObjectPermsResponseSchema": ApiObjectPermsResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    parameters_schema = GetApiObjectRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": ApiObjectPermsResponseSchema}})

    def get(self, controller: SshController, data: dict, oid: str, *args, **kwargs):
        user = controller.get_ssh_user(oid)
        res = user.get_password()
        return {"password": res}


class CreateSshUserParamRequestSchema(ApiBaseSshObjectCreateRequestSchema):
    username = fields.String(required=True)
    password = fields.String(required=True, allow_none=True)
    attribute = fields.String(required=False)
    node_id = fields.String(required=True)
    key_id = fields.String(required=True, allow_none=True)


class CreateSshUserRequestSchema(Schema):
    user = fields.Nested(CreateSshUserParamRequestSchema, context="body")


class CreateSshUserBodyRequestSchema(Schema):
    body = fields.Nested(CreateSshUserRequestSchema, context="body")


class CreateSshUser(SshApiView):
    tags = ["ssh"]
    definitions = {
        "CreateSshUserRequestSchema": CreateSshUserRequestSchema,
        "CrudApiObjectResponseSchema": CrudApiObjectResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(CreateSshUserBodyRequestSchema)
    parameters_schema = CreateSshUserRequestSchema
    responses = SshApiView.setResponses({201: {"description": "success", "schema": CrudApiObjectResponseSchema}})

    def post(self, controller: SshController, data: dict, *args, **kwargs):
        from beehive_ssh.controller import SshController

        sshController: SshController = controller
        resp = sshController.add_ssh_user(**data.get("user"))
        return {"uuid": resp}, 201


class UpdateSshUserParamRequestSchema(ApiBaseSshObjectUpdateRequestSchema):
    username = fields.String(required=False)
    password = fields.String(required=False)
    attribute = fields.String(required=False)
    node_id = fields.String(required=False)
    key_id = fields.String(required=False)


class UpdateSshUserRequestSchema(Schema):
    user = fields.Nested(UpdateSshUserParamRequestSchema)


class UpdateSshUserBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(UpdateSshUserRequestSchema, context="body")


class UpdateSshUser(SshApiView):
    tags = ["ssh"]
    definitions = {
        "UpdateSshUserRequestSchema": UpdateSshUserRequestSchema,
        "CrudApiObjectResponseSchema": CrudApiObjectResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(UpdateSshUserBodyRequestSchema)
    parameters_schema = UpdateSshUserRequestSchema
    responses = SshApiView.setResponses({200: {"description": "success", "schema": CrudApiObjectResponseSchema}})

    def put(self, controller: SshController, data: dict, oid: str, *args, **kwargs):
        user = controller.get_ssh_user(oid)
        data = data.get("user")
        self.logger.warn(data)
        self.logger.warn(user.name)
        resp = user.update(**data)
        return {"uuid": resp}, 200


class DeleteSshUser(SshApiView):
    tags = ["ssh"]
    definitions = {}
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SshApiView.setResponses({204: {"description": "no response"}})

    def delete(self, controller: SshController, data: dict, oid: str, *args, **kwargs):
        user = controller.get_ssh_user(oid)
        self.logger.warn(user.name)
        resp = user.delete(soft=True)
        return resp, 204


class SshUserAPI(ApiView):
    """SshUserAPI"""

    @staticmethod
    def register_api(module, **kwargs):
        base = "gas"
        rules = [
            ("%s/users" % base, "GET", ListSshUsers, {}),
            ("%s/users/<oid>" % base, "GET", GetSshUser, {}),
            ("%s/users/<oid>/perms" % base, "GET", GetSshUserPerms, {}),
            ("%s/users/<oid>/password" % base, "GET", GetSshUserPwd, {}),
            ("%s/users" % base, "POST", CreateSshUser, {}),
            ("%s/users/<oid>" % base, "PUT", UpdateSshUser, {}),
            ("%s/users/<oid>" % base, "DELETE", DeleteSshUser, {}),
        ]

        ApiView.register_api(module, rules, **kwargs)
