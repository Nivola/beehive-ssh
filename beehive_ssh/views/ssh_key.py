# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2022 CSI-Piemonte

from beehive.common.apimanager import ApiView, \
    PaginatedRequestQuerySchema, \
    PaginatedResponseSchema, ApiObjectResponseSchema, \
    CrudApiObjectResponseSchema, GetApiObjectRequestSchema, \
    ApiObjectPermsResponseSchema, ApiObjectPermsRequestSchema, ApiObjectRequestFiltersSchema, \
    CrudApiObjectSimpleResponseSchema
from flasgger import fields, Schema
from beecell.swagger import SwaggerHelper
from beehive_ssh.views import SshApiView, ApiBaseSshObjectCreateRequestSchema


class ListSshKeysRequestSchema(ApiObjectRequestFiltersSchema, PaginatedRequestQuerySchema):
    user_id = fields.String(required=False, context='query')


class ListSshKeysParamsResponseSchema(ApiObjectResponseSchema):
    attribute = fields.String(required=False)
    priv_key = fields.String(required=True)
    pub_key = fields.String(required=True)


class ListSshKeysResponseSchema(PaginatedResponseSchema):
    keys = fields.Nested(ListSshKeysParamsResponseSchema, many=True, required=True, allow_none=True)


class ListSshKeys(SshApiView):
    tags = ['ssh']
    definitions = {
        'ListSshKeysResponseSchema': ListSshKeysResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ListSshKeysRequestSchema)
    parameters_schema = ListSshKeysRequestSchema
    responses = SshApiView.setResponses({
        200: {
            'description': 'success',
            'schema': ListSshKeysResponseSchema
        }
    })
    response_schema = ListSshKeysResponseSchema

    def get(self, controller, data, *args, **kwargs):
        """
        List keys
        Call this api to list all the existing keys
        """

        keys, total = controller.get_ssh_keys(**data)
        res = [r.info() for r in keys]
        return self.format_paginated_response(res, 'keys', total, **data)


class GetSshKeyParamsResponseSchema(ApiObjectResponseSchema):
    priv_key = fields.String(required=True)
    pub_key = fields.String(required=True)
    attribute = fields.String(required=False)
    version = fields.String(required=False)
    attributes = fields.Dict(required=False, default={}, example={})


class GetSshKeyResponseSchema(Schema):
    key = fields.Nested(GetSshKeyParamsResponseSchema, required=True, allow_none=True)


class GetSshKey(SshApiView):
    tags = ['ssh']
    definitions = {
        'GetSshKeyResponseSchema': GetSshKeyResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SshApiView.setResponses({
        200: {
            'description': 'success',
            'schema': GetSshKeyResponseSchema
        }
    })
    response_schema = GetSshKeyResponseSchema

    def get(self, controller, data, oid, *args, **kwargs):
        from beehive_ssh.controller import SshController
        sshController: SshController = controller
        key = sshController.get_ssh_key(oid)
        return {'key': key.detail()}


class GetSshKeyPerms(SshApiView):
    tags = ['ssh']
    definitions = {
        'ApiObjectPermsRequestSchema': ApiObjectPermsRequestSchema,
        'ApiObjectPermsResponseSchema': ApiObjectPermsResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ApiObjectPermsRequestSchema)
    parameters_schema = PaginatedRequestQuerySchema
    responses = SshApiView.setResponses({
        200: {
            'description': 'success',
            'schema': ApiObjectPermsResponseSchema
        }
    })
    # response_schema = ApiObjectPermsResponseSchema

    def get(self, controller, data, oid, *args, **kwargs):
        key = controller.get_ssh_key(oid)
        res, total = key.authorization(**data)
        return self.format_paginated_response(res, 'perms', total, **data)


class CreateSshKeyParamRequestSchema(ApiBaseSshObjectCreateRequestSchema):
    priv_key = fields.String(required=False, missing=None, description='Private key. Use for existing key')
    pub_key = fields.String(required=False, missing=None, description='Public key. Use with priv_key for existing key')
    type = fields.String(required=False, missing='rsa', example='rsa',
                         description='Specify type like rsa, dsa. Use for new key when priv_key is null')
    bits = fields.Integer(required=False, missing=2048, example=2096,
                          description='For new key specify bits like 2096. Use with type')
    attribute = fields.String(required=False)


class CreateSshKeyRequestSchema(Schema):
    key = fields.Nested(CreateSshKeyParamRequestSchema, context='body')


class CreateSshKeyBodyRequestSchema(Schema):
    body = fields.Nested(CreateSshKeyRequestSchema, context='body')


class CreateSshKey(SshApiView):
    tags = ['ssh']
    definitions = {
        'CreateSshKeyRequestSchema': CreateSshKeyRequestSchema,
        'CrudApiObjectResponseSchema':CrudApiObjectResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(CreateSshKeyBodyRequestSchema)
    parameters_schema = CreateSshKeyRequestSchema
    responses = SshApiView.setResponses({
        201: {
            'description': 'success',
            'schema': CrudApiObjectResponseSchema
        }
    })
    response_schema = CrudApiObjectResponseSchema

    def post(self, controller, data, *args, **kwargs):
        resp = controller.add_ssh_key(**data.get('key'))
        return {'uuid': resp}, 201


class UpdateSshKeyParamRequestSchema(ApiBaseSshObjectCreateRequestSchema):
    priv_key = fields.String(required=False)
    pub_key = fields.String(required=False)
    active = fields.Boolean(required=False, default=False)
    openstack_key = fields.String(required=False, description='Openstack key name')


class UpdateSshKeyRequestSchema(Schema):
    key = fields.Nested(UpdateSshKeyParamRequestSchema)


class UpdateSshKeyBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(UpdateSshKeyRequestSchema, context='body')


class UpdateSshKey(SshApiView):
    tags = ['ssh']
    definitions = {
        'UpdateSshKeyRequestSchema':UpdateSshKeyRequestSchema,
        'CrudApiObjectResponseSchema':CrudApiObjectResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(UpdateSshKeyBodyRequestSchema)
    parameters_schema = UpdateSshKeyRequestSchema
    responses = SshApiView.setResponses({
        200: {
            'description': 'success',
            'schema': CrudApiObjectResponseSchema
        }
    })
    # response_schema = CrudApiObjectResponseSchema

    def put(self, controller, data, oid, *args, **kwargs):
        key = controller.get_ssh_key(oid)
        data = data.get('key')
        resp = key.update(**data)
        return {'uuid': resp}, 200


class DeleteSshKey(SshApiView):
    tags = ['ssh']
    definitions = {}
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SshApiView.setResponses({
        204: {
            'description': 'no response'
        }
    })
    # response_schema = 

    def delete(self, controller, data, oid, *args, **kwargs):
        key = controller.get_ssh_key(oid)
        resp = key.delete(soft=True)
        return resp, 204


class GetKeyRolesItemResponseSchema(ApiObjectResponseSchema):
    name = fields.String(required=True, default='master')
    desc = fields.String(required=True, default='')


class GetKeyRolesResponseSchema(Schema):
    roles = fields.Nested(GetKeyRolesItemResponseSchema, required=True, allow_none=True)


class GetKeyRoles(SshApiView):
    tags = ['authority']
    definitions = {
        'GetKeyRolesResponseSchema': GetKeyRolesResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ApiObjectPermsRequestSchema)
    parameters_schema = ApiObjectPermsRequestSchema
    responses = SshApiView.setResponses({
        200: {
            'description': 'success',
            'schema': ApiObjectPermsResponseSchema
        }
    })
    # response_schema = ApiObjectPermsResponseSchema

    def get(self, controller, data, oid, *args, **kwargs):
        """
        List key object permission
        Call this api to list object permissions
        """
        key = controller.get_ssh_key(oid)
        res = key.get_role_templates()
        return {'roles': res, 'count': len(res)}


class GetKeyUsersItemResponseSchema(ApiObjectResponseSchema):
    role = fields.String(required=True, default='master')


class GetKeyUsersResponseSchema(Schema):
    users = fields.Nested(GetKeyUsersItemResponseSchema, required=True, allow_none=True)


class GetKeyUsers(SshApiView):
    tags = ['authority']
    definitions = {
        'GetKeyUsersResponseSchema': GetKeyUsersResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ApiObjectPermsRequestSchema)
    parameters_schema = ApiObjectPermsRequestSchema
    responses = SshApiView.setResponses({
        200: {
            'description': 'success',
            'schema': ApiObjectPermsResponseSchema
        }
    })
    # response_schema = ApiObjectPermsResponseSchema

    def get(self, controller, data, oid, *args, **kwargs):
        """
        List key object permission
        Call this api to list object permissions
        """
        key = controller.get_ssh_key(oid)
        res = key.get_users()
        return {'users': res, 'count': len(res)}


class SetKeyUsersParamRequestSchema(Schema):
    user_id = fields.String(required=False, default='prova', description='User name, id or uuid')
    role = fields.String(required=False, default='prova', description='Role name, id or uuid')


class SetKeyUsersRequestSchema(Schema):
    user = fields.Nested(SetKeyUsersParamRequestSchema)


class SetKeyUsersBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(SetKeyUsersRequestSchema, context='body')


class SetKeyUsers(SshApiView):
    tags = ['authority']
    definitions = {
        'SetKeyUsersRequestSchema': SetKeyUsersRequestSchema,
        'CrudApiObjectSimpleResponseSchema': CrudApiObjectSimpleResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(SetKeyUsersBodyRequestSchema)
    parameters_schema = SetKeyUsersRequestSchema
    responses = SshApiView.setResponses({
        200: {
            'description': 'success',
            'schema': CrudApiObjectSimpleResponseSchema
        }
    })
    # resp: True
    # response_schema = CrudApiObjectSimpleResponseSchema

    def post(self, controller, data, oid, *args, **kwargs):
        """
        Set key user
        Set key user
        """
        from beehive_ssh.controller import ApiSshKey
        key: ApiSshKey = controller.get_ssh_key(oid)
        data = data.get('user')
        resp = key.set_user(**data)
        return True, 200


class UnsetKeyUsersParamRequestSchema(Schema):
    user_id = fields.String(required=False, default='prova', description='User name, id or uuid')
    role = fields.String(required=False, default='prova', description='Role name, id or uuid')


class UnsetKeyUsersRequestSchema(Schema):
    user = fields.Nested(UnsetKeyUsersParamRequestSchema)


class UnsetKeyUsersBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(UnsetKeyUsersRequestSchema, context='body')


class UnsetKeyUsers(SshApiView):
    tags = ['authority']
    definitions = {
        'UnsetKeyUsersRequestSchema': UnsetKeyUsersRequestSchema,
        'CrudApiObjectSimpleResponseSchema': CrudApiObjectSimpleResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(UnsetKeyUsersBodyRequestSchema)
    parameters_schema = UnsetKeyUsersRequestSchema
    responses = SshApiView.setResponses({
        200: {
            'description': 'success',
            'schema': CrudApiObjectSimpleResponseSchema
        }
    })
    # response_schema = CrudApiObjectSimpleResponseSchema

    def delete(self, controller, data, oid, *args, **kwargs):
        """
        Unset key user
        Unset key user
        """
        key = controller.get_ssh_key(oid)
        data = data.get('user')
        resp = key.unset_user(**data)
        return True, 200


class GetKeyGroupsItemResponseSchema(ApiObjectResponseSchema):
    role = fields.String(required=True, default='master')


class GetKeyGroupsResponseSchema(Schema):
    groups = fields.Nested(GetKeyGroupsItemResponseSchema, required=True, allow_none=True)


class GetKeyGroups(SshApiView):
    tags = ['authority']
    definitions = {
        'GetKeyGroupsResponseSchema': GetKeyGroupsResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ApiObjectPermsRequestSchema)
    parameters_schema = ApiObjectPermsRequestSchema
    responses = SshApiView.setResponses({
        200: {
            'description': 'success',
            'schema': ApiObjectPermsResponseSchema
        }
    })
    # response_schema = ApiObjectPermsResponseSchema

    def get(self, controller, data, oid, *args, **kwargs):
        """
        List group object permission
        Call this api to list object permissions
        """
        group = controller.get_ssh_key(oid)
        res = group.get_groups()
        return {'groups': res, 'count': len(res)}


class SetKeyGroupsParamRequestSchema(Schema):
    group_id = fields.String(required=False, default='prova', description='Key name, id or uuid')
    role = fields.String(required=False, default='prova', description='Role name, id or uuid')


class SetKeyGroupsRequestSchema(Schema):
    group = fields.Nested(SetKeyGroupsParamRequestSchema)


class SetKeyGroupsBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(SetKeyGroupsRequestSchema, context='body')


class SetKeyGroups(SshApiView):
    tags = ['authority']
    definitions = {
        'SetKeyGroupsRequestSchema': SetKeyGroupsRequestSchema,
        'CrudApiObjectSimpleResponseSchema': CrudApiObjectSimpleResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(SetKeyGroupsBodyRequestSchema)
    parameters_schema = SetKeyGroupsRequestSchema
    responses = SshApiView.setResponses({
        200: {
            'description': 'success',
            'schema': CrudApiObjectSimpleResponseSchema
        }
    })
    # response_schema = CrudApiObjectSimpleResponseSchema

    def post(self, controller, data, oid, *args, **kwargs):
        """
        Set group group
        Set group group
        """
        group = controller.get_ssh_key(oid)
        data = data.get('group')
        resp = group.set_group(**data)
        return True, 200


class UnsetKeyGroupsParamRequestSchema(Schema):
    group_id = fields.String(required=False, default='prova', description='Group name, id or uuid')
    role = fields.String(required=False, default='prova', description='Role name, id or uuid')


class UnsetKeyGroupsRequestSchema(Schema):
    group = fields.Nested(UnsetKeyGroupsParamRequestSchema)


class UnsetKeyGroupsBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(UnsetKeyGroupsRequestSchema, context='body')


class UnsetKeyGroups(SshApiView):
    tags = ['authority']
    definitions = {
        'UnsetKeyGroupsRequestSchema': UnsetKeyGroupsRequestSchema,
        'CrudApiObjectSimpleResponseSchema': CrudApiObjectSimpleResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(UnsetKeyGroupsBodyRequestSchema)
    parameters_schema = UnsetKeyGroupsRequestSchema
    responses = SshApiView.setResponses({
        200: {
            'description': 'success',
            'schema': CrudApiObjectSimpleResponseSchema
        }
    })
    # response_schema = CrudApiObjectSimpleResponseSchema

    def delete(self, controller, data, oid, *args, **kwargs):
        """
        Unset group group
        Unset group group
        """
        group = controller.get_ssh_key(oid)
        data = data.get('group')
        resp = group.unset_group(**data)
        return True, 200


class SshKeyAPI(ApiView):
    """SshKeyAPI
    """
    @staticmethod
    def register_api(module, **kwargs):
        base = 'gas'
        rules = [
            ('%s/keys' % base, 'GET', ListSshKeys, {}),
            ('%s/keys/<oid>' % base, 'GET', GetSshKey, {}),
            ('%s/keys' % base, 'POST', CreateSshKey, {}),
            ('%s/keys/<oid>' % base, 'PUT', UpdateSshKey, {}),
            ('%s/keys/<oid>' % base, 'DELETE', DeleteSshKey, {}),

            ('%s/keys/<oid>/perms' % base, 'GET', GetSshKeyPerms, {}),
            ('%s/keys/<oid>/roles' % base, 'GET', GetKeyRoles, {}),
            ('%s/keys/<oid>/users' % base, 'GET', GetKeyUsers, {}),
            ('%s/keys/<oid>/users' % base, 'POST', SetKeyUsers, {}),
            ('%s/keys/<oid>/users' % base, 'DELETE', UnsetKeyUsers, {}),
            ('%s/keys/<oid>/groups' % base, 'GET', GetKeyGroups, {}),
            ('%s/keys/<oid>/groups' % base, 'POST', SetKeyGroups, {}),
            ('%s/keys/<oid>/groups' % base, 'DELETE', UnsetKeyGroups, {}),
        ]

        ApiView.register_api(module, rules, **kwargs)
