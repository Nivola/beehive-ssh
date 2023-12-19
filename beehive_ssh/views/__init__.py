# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2023 CSI-Piemonte

from flasgger import fields, Schema

from beehive.common.apimanager import SwaggerApiView


class SshApiView(SwaggerApiView):
    pass


class ApiBaseSshObjectCreateRequestSchema(Schema):
    name = fields.String(required=False)
    desc = fields.String(required=False, allow_none=True)
    active = fields.Boolean(required=False, allow_none=True)


class ApiBaseSshObjectUpdateRequestSchema(Schema):
    name = fields.String(required=False, allow_none=True)
    desc = fields.String(required=False, allow_none=True)
    active = fields.Boolean(required=False, allow_none=True)
