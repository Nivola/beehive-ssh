# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2022 CSI-Piemonte

from beehive.common.apimanager import ApiView, ApiObjectResponseSchema,  GetApiObjectRequestSchema, \
    CrudApiObjectSimpleResponseSchema
from flasgger import fields, Schema
from beecell.swagger import SwaggerHelper
from beehive_ssh.views import SshApiView


class GetUserPermsResponseSchema(ApiObjectResponseSchema):
    ip_address = fields.String(required=True)
    node_id = fields.String(required=True)
    username = fields.String(required=True)
    attribute = fields.String(required=False)


class GetUserPermsResponseSchema(Schema):
    perms = fields.Dict() # fields.Nested(GetSshLoginParamsResponseSchema, required=True, allow_none=True)


class GetUserPerms(SshApiView):
    tags = ['ssh']
    definitions = {
        'GetUserPermsResponseSchema': GetUserPermsResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SshApiView.setResponses({
        200: {
            'description': 'success',
            'schema': GetUserPermsResponseSchema
        }
    })

    def get(self, controller, data, oid, *args, **kwargs):
        perms = controller.get_user_perms(oid)
        return {'perms': perms}


class SetUserPermRequestSchema(Schema):
    type = fields.String(required=True)
    value = fields.String(required=True)


class SetUserPermsRequestSchema(Schema):
    perms = fields.Nested(SetUserPermRequestSchema, many=True, required=True, allow_none=True)


class SetUserPermsBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(SetUserPermsRequestSchema, context='body')


class SetUserPerms(SshApiView):
    tags = ['ssh']
    definitions = {
        'SetUserPermsRequestSchema': SetUserPermsRequestSchema,
        'CrudApiObjectSimpleResponseSchema': CrudApiObjectSimpleResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(SetUserPermsBodyRequestSchema)
    parameters_schema = SetUserPermsRequestSchema
    responses = SshApiView.setResponses({
        200: {
            'description': 'success',
            'schema': CrudApiObjectSimpleResponseSchema
        }
    })

    def post(self, controller, data, oid, *args, **kwargs):
        resp = controller.assign_user_perms(oid, data.get('perms'))
        return {'uuid': resp}, 200


class UnSetUserPermRequestSchema(Schema):
    type = fields.String(required=True)
    value = fields.String(required=True)


class UnSetUserPermsRequestSchema(Schema):
    perms = fields.Nested(UnSetUserPermRequestSchema, many=True, required=True, allow_none=True)


class UnSetUserPermsBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(UnSetUserPermsRequestSchema, context='body')


class UnSetUserPerms(SshApiView):
    tags = ['ssh']
    definitions = {
        'UnSetUserPermsRequestSchema': UnSetUserPermsRequestSchema,
        'CrudApiObjectSimpleResponseSchema': CrudApiObjectSimpleResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(UnSetUserPermsBodyRequestSchema)
    parameters_schema = UnSetUserPermsRequestSchema
    responses = SshApiView.setResponses({
        200: {
            'description': 'success',
            'schema': CrudApiObjectSimpleResponseSchema
        }
    })

    def delete(self, controller, data, oid, *args, **kwargs):
        resp = controller.deassign_user_perms(oid, data.get('perms'))
        return {'uuid': resp}, 200


class GetRolePermsResponseSchema(ApiObjectResponseSchema):
    ip_address = fields.String(required=True)
    node_id = fields.String(required=True)
    rolename = fields.String(required=True)
    attribute = fields.String(required=False)


class GetRolePermsResponseSchema(Schema):
    perms = fields.Dict()  # fields.Nested(GetSshLoginParamsResponseSchema, required=True, allow_none=True)


class GetRolePerms(SshApiView):
    tags = ['ssh']
    definitions = {
        'GetRolePermsResponseSchema': GetRolePermsResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SshApiView.setResponses({
        200: {
            'description': 'success',
            'schema': GetRolePermsResponseSchema
        }
    })

    def get(self, controller, data, oid, *args, **kwargs):
        perms = controller.get_role_perms(oid)
        return {'perms': perms}


class SetRolePermRequestSchema(Schema):
    type = fields.String(required=True)
    value = fields.String(required=True)


class SetRolePermsRequestSchema(Schema):
    perms = fields.Nested(SetRolePermRequestSchema, many=True, required=True, allow_none=True)


class SetRolePermsBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(SetRolePermsRequestSchema, context='body')


class SetRolePerms(SshApiView):
    tags = ['ssh']
    definitions = {
        'SetRolePermsRequestSchema': SetRolePermsRequestSchema,
        'CrudApiObjectSimpleResponseSchema': CrudApiObjectSimpleResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(SetRolePermsBodyRequestSchema)
    parameters_schema = SetRolePermsRequestSchema
    responses = SshApiView.setResponses({
        200: {
            'description': 'success',
            'schema': CrudApiObjectSimpleResponseSchema
        }
    })

    def post(self, controller, data, oid, *args, **kwargs):
        resp = controller.assign_role_perms(oid, data.get('perms'))
        return {'uuid': resp}, 200


class UnSetRolePermRequestSchema(Schema):
    type = fields.String(required=True)
    value = fields.String(required=True)


class UnSetRolePermsRequestSchema(Schema):
    perms = fields.Nested(UnSetRolePermRequestSchema, many=True, required=True, allow_none=True)


class UnSetRolePermsBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(UnSetRolePermsRequestSchema, context='body')


class UnSetRolePerms(SshApiView):
    tags = ['ssh']
    definitions = {
        'UnSetRolePermsRequestSchema': UnSetRolePermsRequestSchema,
        'CrudApiObjectSimpleResponseSchema': CrudApiObjectSimpleResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(UnSetRolePermsBodyRequestSchema)
    parameters_schema = UnSetRolePermsRequestSchema
    responses = SshApiView.setResponses({
        200: {
            'description': 'success',
            'schema': CrudApiObjectSimpleResponseSchema
        }
    })

    def delete(self, controller, data, oid, *args, **kwargs):
        resp = controller.deassign_role_perms(oid, data.get('perms'))
        return {'uuid': resp}, 200


class SshPermAPI(ApiView):
    """SshPermAPI
    """
    @staticmethod
    def register_api(module, **kwargs):
        base = 'gas'
        rules = [
            ('%s/sshperms/<oid>' % base, 'GET', GetUserPerms, {}),
            ('%s/sshperms/<oid>' % base, 'POST', SetUserPerms, {}),
            ('%s/sshperms/<oid>' % base, 'DELETE', UnSetUserPerms, {}),

            ('%s/perms/user/<oid>' % base, 'GET', GetUserPerms, {}),
            ('%s/perms/user/<oid>' % base, 'POST', SetUserPerms, {}),
            ('%s/perms/user/<oid>' % base, 'DELETE', UnSetUserPerms, {}),

            ('%s/perms/role/<oid>' % base, 'GET', GetRolePerms, {}),
            ('%s/perms/role/<oid>' % base, 'POST', SetRolePerms, {}),
            ('%s/perms/role/<oid>' % base, 'DELETE', UnSetRolePerms, {}),
        ]

        ApiView.register_api(module, rules, **kwargs)
