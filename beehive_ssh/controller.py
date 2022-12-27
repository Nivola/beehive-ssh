# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2022 CSI-Piemonte

from copy import deepcopy
from six.moves.urllib.parse import urlencode
import ujson as json
from beehive.common.apiclient import BeehiveApiClientError
from beehive.common.apimanager import ApiObject, ApiController, ApiManagerError
from beehive.common.event import Event
from beehive_ssh.dao.SshDao import SshDbManager
from beehive.common.data import trace, TransactionError, operation
from beehive_ssh.model import SshGroup, SshNode, SshUser, SshKey
from beecell.types.type_dict import dict_get
from beecell.types.type_id import id_gen
from beecell.types.type_string import truncate
from six import StringIO, ensure_binary
from base64 import b64encode
from paramiko import DSSKey, ECDSAKey, RSAKey
from paramiko.ssh_exception import SSHException


class SshController(ApiController):
    """Service Module controller.
    """
    version = 'v1.0'

    def __init__(self, module):
        ApiController.__init__(self, module)

        self.manager = SshDbManager()

        self.child_classes = [
            ApiSshGroup,
            ApiSshKey
        ]

    def populate(self, db_uri):
        """Populate initial data in service database

        :param db_uri: database uri
        :return:
        """
        self.manager.populate(db_uri)

    @trace(entity='ApiSshGroup', op='view')
    def get_ansible_inventory(self, group=None, node=None, node_name=None):
        """Get ansible dynamic inventory.

        :param node: node reference
        :param group: group reference
        :param node_name: node name pattern
        :return: dict with ansible inventory
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        objs = self.can('view', objtype=SshApiObject.objtype)

        # get filters
        if group is not None:
            group = self.get_ssh_group(group).oid
        elif node is not None:
            node = self.get_ssh_node(node).oid

        # query database
        nodegroups = self.manager.get_nodes_and_groups(node=node, group=group, node_name=node_name)
        inventory_dict = {
            'all': {
                'hosts': [],
                'vars': {
                    'ansible_user': None,
                    #'ansible_ssh_private_key_file': None,
                    #'ansible_ssh_private_key_files': {},
                }
            },
            '_meta': {
                'hostvars': {}
            }
        }

        # function to check permissions
        def check(objs, objdef, objid):
            objset = set(objs.get(objdef.lower(), []))

            # create needs
            needs = self.get_needs(objid.split('//'))

            # check if needs overlaps perms
            res = self.has_needs(needs, objset)
            return res

        for nodegroup in nodegroups:
            node = nodegroup[0]
            user = nodegroup[1]
            key = nodegroup[2]
            group = nodegroup[3]

            # check authorization for group
            # self.logger.debug2('Check group permission for group %s' % group.objid)
            if check(objs, ApiSshGroup.objdef, group.objid) is False:
                continue

            # check authorization for key
            # self.logger.debug2('Check key permission for key %s' % key.objid)
            if check(objs, ApiSshKey.objdef, key.objid) is False:
                continue

            # append to all group
            if node.name not in inventory_dict['all']['hosts']:
                inventory_dict['all']['hosts'].append(node.name)

            try:
                inventory_dict[group.name]['hosts'].append(node.name)
            except:
                inventory_dict[group.name] = {'hosts': [node.name]}

            vars = {
                'ansible_user': user.username,
                'ansible_password': self.decrypt_data(user.password),
                'ansible_user_key_id': key.name,
            }
            inventory_dict['_meta']['hostvars'][node.name] = vars
            # inventory_dict['all']['vars']['ansible_ssh_private_key_files'][key.name] = key.priv_key

        return inventory_dict

    @trace(entity='ApiSshGroup', op='view')
    def get_ssh_group(self, oid):
        """Get single ssh group.

        :param oid: entity model id, uuid
        :return: SshGroup
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        ssh_group = self.get_entity(ApiSshGroup, SshGroup, oid)
        return ssh_group
    
    @trace(entity='ApiSshGroup', op='view')
    def get_paginated_ssh_groups(self, *args, **kvargs):
        
        def findSshGroups(*args, **kvargs):
            entities, total = self.manager.get_paginated_ssh_groups(*args, **kvargs)
            return entities, total                    
             
        res, total = self.get_paginated_entities(ApiSshGroup, findSshGroups, *args, **kvargs)
        return res, total
    
    @trace(entity='ApiSshNode', op='view')
    def get_ssh_node(self, oid):
        """Get single ssh group.

        :param oid: entity model id, uuid
        :return: SshNode
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        
        ssh_node = self.get_entity(ApiSshNode, SshNode, oid)
        return ssh_node
    
    @trace(entity='ApiSshNode', op='view')
    def get_ssh_nodes(self, *args, **kvargs):
        
        def find_ssh_nodes(*args, **kvargs):
            group_id = kvargs.get('group_id', None)
            if group_id is not None:
                kvargs['group_id'] = self.get_ssh_group(group_id).oid

            key_id = kvargs.get('key_id', None)
            if key_id is not None:
                kvargs['key_id'] = self.get_ssh_key(key_id).oid

            entities, total = self.manager.get_paginated_nodes(*args, **kvargs)
            return entities, total  

        res, total = self.get_paginated_entities(ApiSshNode, find_ssh_nodes, *args, **kvargs)
        return res, total

    @trace(entity='ApiSshNode', op='use')
    def get_ssh_node_actions(self, node_id=None, *args, **kvargs):
        """Get node actions

        :param date: day to query. Syntax YYYY.MM.DD
        :param page: query page [default=0]
        :param size: query size [default=20]
        :return:
        """
        self.can('use', objtype=ApiSshNode.objtype, definition=ApiSshNode.objdef).get(ApiSshNode.objdef)

        kvargs = {
            'date': kvargs.get('date'),
            'size': kvargs.get('size'),
            'page': kvargs.get('page'),
            'event_type': 'SSH',
            'input': node_id
        }
        events = Event.get_from_elastic(self.api_manager.app_env, self.api_manager.elasticsearch, **kvargs)
        res = []
        for event in events.get('values'):
            data = event.data
            params = json.loads(data.get('kwargs', '{}'))
            status = data.get('response', None)
            if status[0] is True:
                status = 'OK'
            else:
                msg = ''
                if isinstance(status, list):
                    msg = ' - %s' % status[1]
                status = 'KO' + msg
            res.append({
                'id': event.id,
                'date': event.creation,
                'user': event.source,
                'action_id': data.get('opid', None),
                'action': data.get('op', None),
                'elapsed': data.get('elapsed', None),
                'node_id': params.get('node_id', None),
                'node_name': params.get('node_name', None),
                'node_user': params.get('user', '').split('.')[0],
                'status': status
            })
        return res, events.get('total')

    # def get_ssh_node_actions(self, node_id=None, *args, **kvargs):
    #     self.can('use', objtype=ApiSshNode.objtype, definition=ApiSshNode.objdef).get(ApiSshNode.objdef)
    #
    #     try:
    #         data = {
    #             'objtype': 'ssh',
    #             'objdef': 'SshGroup.SshNode',
    #             'type': 'SSH'
    #         }
    #         if node_id is not None:
    #             data['data'] = '%' + node_id + '%'
    #         data.update(kvargs)
    #         events = self.api_client.user_request('event', '/v1.0/nes/events', 'get', data=urlencode(data))
    #         event_tot = events.get('total', 0)
    #         events = events.get('events', [])
    #         self.logger.debug('Get events related to node accesses %s' % truncate(events))
    #     except BeehiveApiClientError as ex:
    #         self.logger.warn('No events related to node accesses', exc_info=1)
    #         event_tot = 0
    #         events = []
    #
    #     res = []
    #     for event in events:
    #         data = event.get('data', {})
    #         params = data.get('params', {})
    #         status = data.get('response', None)
    #         if status is True:
    #             status = 'OK'
    #         else:
    #             msg = ''
    #             if isinstance(status, list):
    #                 msg = ' - %s' % status[1]
    #             status = 'KO' + msg
    #         res.append({
    #             'id': event.get('event_id', None),
    #             'date': event.get('date', None),
    #             'user': event.get('source', None),
    #             'action_id': data.get('opid', None),
    #             'action': data.get('op', None),
    #             'elapsed': data.get('elapsed', None),
    #             'node_id': params.get('node_id', None),
    #             'node_name': params.get('node_name', None),
    #             'node_user': params.get('user', None),
    #             'status': status
    #         })
    #
    #     return res, event_tot

    @trace(entity='ApiSshUser', op='view')
    def get_ssh_user(self, oid):
        """Get single ssh user.

        :param oid: entity model id, uuid
        :return: SshUser
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        def find_ssh_users(*args, **kvargs):
            kvargs['user_id'] = oid
            entities, total = self.manager.get_paginated_users(*args, **kvargs)
            return entities, total

        entities, total = self.get_paginated_entities(ApiSshUser, find_ssh_users)
        if total == 0:
            raise ApiManagerError('node user %s was not found' % oid)
        ssh_user = entities[0]
        # ssh_user = self.get_entity(ApiSshUser, SshUser, oid)
        return ssh_user
    
    @trace(entity='ApiSshUser', op='view')
    def get_ssh_users(self, *args, **kvargs):
        """List users

        :param args:
        :param kvargs:
        :return:
        """
        def find_ssh_users(*args, **kvargs):
            node_id = kvargs.pop('node_id', None)
            if node_id is not None:
                kvargs['node_id'] = self.get_ssh_node(node_id).oid

            entities, total = self.manager.get_paginated_users(*args, **kvargs)
            return entities, total

        res, total = self.get_paginated_entities(ApiSshUser, find_ssh_users, *args, **kvargs)
        return res, total

    @trace(entity='ApiSshKey', op='view')
    def get_ssh_key(self, oid):
        """Get single ssh key.

        :param oid: entity model id, uuid
        :return: SshKey
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """

        ssh_key = self.get_entity(ApiSshKey, SshKey, oid)
        return ssh_key

    @trace(entity='ApiSshKey', op='view')
    def get_ssh_keys(self, *args, **kvargs):
        """Get ssh keys

        :param args:
        :param kvargs:
        :return:
        """
        def find_sh_keys(*args, **kvargs):
            user_id = kvargs.pop('user_id', None)
            if user_id is not None:
                kvargs['user_id'] = self.get_ssh_user(user_id).oid

            entities, total = self.manager.get_paginated_keys(*args, **kvargs)
            return entities, total

        res, total = self.get_paginated_entities(ApiSshKey, find_sh_keys, *args, **kvargs)
        return res, total

    @trace(entity='ApiSshGroup', op='insert')
    def add_ssh_group(self, name, desc='', attribute=None, active=True):
        """Add new group.

        :param name: group name
        :param desc: group description
        :param attribute: group attribute values
        :return: group uuid
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        # check authorization
        if operation.authorize is True:
            self.check_authorization(ApiSshGroup.objtype, ApiSshGroup.objdef, None, 'insert')

        try:
            objid = '%s' % id_gen()
            group = SshGroup(objid, name=name, desc=desc, active=active, attribute=attribute)
            self.manager.add(group)
            # add object and permission
            ApiSshGroup(self, oid=group.id).register_object(objid.split('//'), desc=name)
            self.logger.debug('Add new ssh_group: %s' % name)

            # self.awx_client.add_team(name, description=desc)

            return group.uuid
        except TransactionError as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=ex.code)
        except Exception as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=400)

    @trace(entity='ApiSshNode', op='insert')
    def add_ssh_node(self, group_id, name, node_type='', ip_address='', desc='', attribute=None, active=True):
        """Add new node.

        :param name: sshnode name
        :param group_id: group group_id group identity
        :param node_type: sshnode type of node
        :param ip_address: sshnode ip_address of the node
        :param desc: sshnode generic description
        :param attribute: sshnode attribute values
        :return: node uuid
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        group = self.get_ssh_group(group_id)

        # check authorization
        if operation.authorize is True:
            self.check_authorization(ApiSshNode.objtype, ApiSshNode.objdef, group.objid, 'insert')
        try:
            objid = '%s//%s' % (group.objid, id_gen())
            node = SshNode(objid, name, active, desc, attribute, node_type, ip_address, group.model)
            self.manager.add(node)
            # if group:
            #     node.groups.append(group.model)
            # add object and permission
            ApiSshNode(self, oid=node.id).register_object(objid.split('//'), desc=name)

            self.logger.debug('Add new ssh_node: %s' % name)
            return node.uuid
        except TransactionError as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=ex.code)
        except Exception as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=400)

    @trace(entity='ApiSshUser', op='insert')
    def add_ssh_user(self, node_id, key_id, name, username, password, attribute, desc=''):
        """Add new user.

        :param name: sshuser name
        :param node_id: sshuser node_id sshnode identity
        :param key_id: sshkey key_id oid key identity
        :param username: sshuser username
        :param password: sshuser password user
        :param attribute: sshuser attribute values
        :return: user uuid
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        node = self.get_ssh_node(node_id)

        # check authorization
        if operation.authorize is True:
            self.check_authorization(ApiSshUser.objtype, ApiSshUser.objdef, node.objid, 'insert')
        try:
            objid = '%s//%s' % (node.objid, id_gen())
            password = self.encrypt_data(password)
            user = SshUser(objid, name, username, password, attribute, desc)
            user.node_id = node.oid
            if key_id is not None:
                key = self.get_ssh_key(key_id)
                user.key.append(key.model)
            else:
                self.logger.warn('Ssh key was not specified for user %s' % name)

            self.manager.add(user)
            # add object and permission

            ApiSshUser(self, oid=user.id).register_object(objid.split('//'), desc=name)

            self.logger.debug('Add new ssh_user: %s' % name)
            return user.uuid
        except TransactionError as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=ex.code)
        except Exception as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=400)

    @trace(entity='ApiSshKey', op='insert')
    def add_ssh_key(self, priv_key=None, pub_key=None, type='rsa', bits=2048, name=None, desc='', attribute=None):
        """Add new key.

        :param name: sshkey name
        :param priv_key: sshkey private key. Use for existing key [optional]
        :param pub_key: sshkey public key. Use with priv_key for existing key [optional]
        :param type: For new key specify type like rsa, dsa. Use for new key when priv_key is None [default=rsa]
        :param bits: For new key specify bits like 2048. Use with type [default=2096]
        :param desc: sshkey description
        :param attribute: sshkey attribute values
        :return: sshkey uuid
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        # check authorization
        if operation.authorize is True:
            self.check_authorization(ApiSshKey.objtype, ApiSshKey.objdef, None, 'insert')

        try:
            objid = '%s' % (id_gen())
            if priv_key is None:
                # create new priv e pub key
                key_dispatch_table = {'dsa': DSSKey, 'rsa': RSAKey, 'ECDSA': ECDSAKey}

                if type not in key_dispatch_table:
                    raise SSHException('Unknown %s algorithm to generate keys pair' % type)

                # generating private key
                prv = key_dispatch_table[type].generate(bits=bits)
                file_obj = StringIO()
                prv.write_private_key(file_obj)
                priv_key = b64encode(ensure_binary(file_obj.getvalue()))
                file_obj.close()

                # get public key
                ssh_key = '%s %s' % (prv.get_name(), prv.get_base64())
                pub_key = b64encode(ensure_binary(ssh_key))
            # else:
            #     raise Exception('Secret key or key type must be specified')
            key = SshKey(objid, priv_key, pub_key, name, desc, attribute)
            self.manager.add(key)

            # add object and permission
            ApiSshKey(self, oid=key.id).register_object(objid.split('//'), desc=name)

            # self.awx_client.add_ssh_credentials(name=name, description=desc,
            #                                     ssh_key_data=priv_key,
            #                                     username="root", password=None,
            #                                     become_method='sudo',
            #                                     organizationid=self.awx_client.organization)

            self.logger.debug('Add new ssh_key: %s' % name)
            return key.uuid
        except TransactionError as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=ex.code)
        except Exception as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=400)

    # Questa sara la add key
    def create_ssh_key(self):
        pass


class SshApiObject(ApiObject):
    module = 'SshModule'
    objtype = 'ssh'

    SSH_OPERATION = 'SSH'

    manager = SshDbManager()

    def __init__(self, *args, **kvargs):
        """ """
        ApiObject.__init__(self, *args, **kvargs)

        self.version = None
        self.attribs = None
        if self.model is not None:
            self.version = getattr(self.model, 'version', '1.0')
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
        info.update({
            'version': self.version,
            'attributes': self.attribs
        })
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
            name = '%s-%s-DELETED' % (self.name, id_gen())
            self.update_object(oid=self.oid, name=name)
            self.logger.debug('Update name of %s to %s' % (self.uuid, name))
        return True

    #
    # authorization
    #
    def get_role_templates(self):
        res = []
        for k, v in self.role_templates.items():
            res.append({'name': k, 'desc': v.get('desc')})
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
            self.verify_permisssions('update')

            # get users
            for tmpl, role in self.role_templates.items():
                perms = []
                for op in role.get('perms'):
                    p = deepcopy(op)
                    objid = p['objid'].replace('<objid>', self.objid)
                    perms.append('%s,%s,%s,%s' % (p['subsystem'], p['type'], objid, p['action']))
                users = self.api_client.get_perms_users(perms)
                for user in users:
                    user['role'] = tmpl
                    res.append(user)
        except BeehiveApiClientError:
            self.logger.error('Error get %s %s users' % (self.objname, self.name), exc_info=1)
            raise ApiManagerError('Error get %s %s users' % (self.objname, self.name))
        self.logger.debug('Get %s %s users: %s' % (self.objname, self.name, truncate(users)))
        return res

    def set_user(self, user_id=None, role=None):
        try:
            self.verify_permisssions('update')

            if role not in self.get_role_template_names():
                raise ApiManagerError('Role %s not found or can not be used' % role)

            # get perms
            role = self.role_templates.get(role)
            perms = []
            for op in role.get('perms'):
                p = deepcopy(op)
                p['objid'] = p['objid'].replace('<objid>', self.objid)
                perms.append(p)
            res = self.api_client.append_user_permissions(user_id, perms)
        except BeehiveApiClientError:
            self.logger.error('Error set %s %s users' % (self.objname, self.name), exc_info=1)
            raise ApiManagerError('Error set %s %s users' % (self.objname, self.name))
        self.logger.debug('Set %s %s users: %s' % (self.objname, self.name, res))
        return True

    def unset_user(self, user_id=None, role=None):
        try:
            self.verify_permisssions('update')

            if role not in self.get_role_template_names():
                raise ApiManagerError('Role %s not found or can not be used' % role)

            # get perms
            role = self.role_templates.get(role)
            perms = []
            for op in role.get('perms'):
                p = deepcopy(op)
                p['objid'] = p['objid'].replace('<objid>', self.objid)
                perms.append(p)

            res = self.api_client.remove_user_permissions(user_id, perms)
        except BeehiveApiClientError:
            self.logger.error('Error unset %s %s users' % (self.objname, self.name), exc_info=1)
            raise ApiManagerError('Error unset %s %s users' % (self.objname, self.name))
        self.logger.debug('Unset %s %s users: %s' % (self.objname, self.name, res))
        return True

    def get_groups(self):
        res = []
        try:
            self.verify_permisssions('update')

            # get groups
            for tmpl, role in self.role_templates.items():
                perms = []
                for op in role.get('perms'):
                    p = deepcopy(op)
                    objid = p['objid'].replace('<objid>', self.objid)
                    perms.append('%s,%s,%s,%s' % (p['subsystem'], p['type'], objid, p['action']))
                self.logger.warn(perms)
                groups = self.api_client.get_perms_groups(perms)
                for group in groups:
                    group['role'] = tmpl
                    res.append(group)
        except BeehiveApiClientError:
            self.logger.error('Error get %s %s groups' % (self.objname, self.name), exc_info=1)
            raise ApiManagerError('Error get %s %s groups' % (self.objname, self.name))
        self.logger.debug('Get %s %s groups: %s' % (self.objname, self.name, truncate(groups)))
        return res

    def set_group(self, group_id=None, role=None):
        try:
            self.verify_permisssions('update')

            if role not in self.get_role_template_names():
                raise ApiManagerError('Role %s not found or can not be used' % role)

            # get perms
            role = self.role_templates.get(role)
            perms = []
            for op in role.get('perms'):
                p = deepcopy(op)
                p['objid'] = p['objid'].replace('<objid>', self.objid)
                perms.append(p)

            res = self.api_client.append_group_permissions(group_id, perms)
        except BeehiveApiClientError:
            self.logger.error('Error set %s %s groups' % (self.objname, self.name), exc_info=1)
            raise ApiManagerError('Error set %s %s groups' % (self.objname, self.name))
        self.logger.debug('Set %s %s groups: %s' % (self.objname, self.name, res))
        return True

    def unset_group(self, group_id=None, role=None):
        try:
            self.verify_permisssions('update')

            if role not in self.get_role_template_names():
                raise ApiManagerError('Role %s not found or can not be used' % role)

            # get perms
            role = self.role_templates.get(role)
            perms = []
            for op in role.get('perms'):
                p = deepcopy(op)
                p['objid'] = p['objid'].replace('<objid>', self.objid)
                perms.append(p)

            res = self.api_client.remove_group_permissions(group_id, perms)
        except BeehiveApiClientError:
            self.logger.error('Error unset %s %s groups' % (self.objname, self.name), exc_info=1)
            raise ApiManagerError('Error unset %s %s groups' % (self.objname, self.name))
        self.logger.debug('Unset %s %s groups: %s' % (self.objname, self.name, res))
        return True


class ApiSshGroup(SshApiObject):
    objdef = 'SshGroup'
    objuri = 'gas/groups'
    objname = 'sshgroup'
    objdesc = 'sshgroup'

    role_templates = {
        'ApiSuperAdmin': {
            'desc': 'Super administrator. Can all',
            'name': 'ApiSuperAdminRole',
            'perms': [
                {'subsystem': 'ssh', 'type': 'SshGroup', 'objid': '*', 'action': '*'},
                {'subsystem': 'ssh', 'type': 'SshGroup.SshNode', 'objid': '*//*', 'action': '*'},
                {'subsystem': 'ssh', 'type': 'SshGroup.SshNode.SshUser', 'objid': '*//*//*', 'action': '*'},
            ],
        },
        'master': {
            'desc': 'Group administrator. Can list and update group, can list child nodes, can connect and execute '
                    'command over child nodes (each users), can manage nodes, can manage node\'s users, can assign '
                    'node to other users, can view node actions',
            'name': 'GroupAdminRole',
            'perms': [
                {'subsystem': 'ssh', 'type': 'SshGroup', 'objid': '<objid>', 'action': 'view'},
                {'subsystem': 'ssh', 'type': 'SshGroup', 'objid': '<objid>', 'action': 'update'},
                {'subsystem': 'ssh', 'type': 'SshGroup.SshNode', 'objid': '<objid>' + '//*',
                 'action': 'view'},
                {'subsystem': 'ssh', 'type': 'SshGroup.SshNode', 'objid': '<objid>' + '//*',
                 'action': 'use'},
                {'subsystem': 'ssh', 'type': 'SshGroup.SshNode', 'objid': '<objid>' + '//*',
                 'action': 'update'},
                {'subsystem': 'ssh', 'type': 'SshGroup.SshNode.SshUser', 'objid': '<objid>' + '//*//*',
                 'action': '*'},
            ],
        },
        'connect': {
            'desc': 'Group connect. Can list group, can list child nodes, can connect and execute command over child '
                    'nodes (each users), can view node actions',
            'name': 'GroupConnectRole',
            'perms': [
                {'subsystem': 'ssh', 'type': 'SshGroup', 'objid': '<objid>', 'action': 'view'},
                {'subsystem': 'ssh', 'type': 'SshGroup.SshNode', 'objid': '<objid>' + '//*',
                 'action': 'view'},
                {'subsystem': 'ssh', 'type': 'SshGroup.SshNode', 'objid': '<objid>' + '//*',
                 'action': 'use'},
                {'subsystem': 'ssh', 'type': 'SshGroup.SshNode.SshUser', 'objid': '<objid>' + '//*//*',
                 'action': 'view'},
            ],
        },
        'viewer': {
            'desc': 'Group viewer. Can list group, can list child nodes, can execute simple command over node (like '
                    'show log) (each users)',
            'name': 'GroupViewerRole',
            'perms': [
                {'subsystem': 'ssh', 'type': 'SshGroup', 'objid': '<objid>', 'action': 'view'},
                {'subsystem': 'ssh', 'type': 'SshGroup.SshNode', 'objid': '<objid>' + '//*',
                 'action': 'view'}
            ]
        }
    }
    role_templates_exclusions = ['ApiSuperAdmin']

    def __init__(self, *args, **kvargs):
        """ """
        SshApiObject.__init__(self, *args, **kvargs)
        # child classes
        self.child_classes = [ApiSshNode]

        self.update_object = self.manager.update_ssh_group
        self.delete_object = self.manager.delete

    def info(self):
        """Get object info

        :return: Dictionary with object info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = SshApiObject.info(self)

        return info

    def detail(self):
        """Get object extended info

        :return: Dictionary with object detail.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = self.info()
        if self.model is not None:
            info['attribute'] = self.model.attribute
        return info

    def pre_delete(self, *args, **kvargs):
        """Pre delete function. This function is used in delete method. Extend
        this function to manipulate and validate delete input params.

        :param args: custom params
        :param kvargs: custom params
        :return: kvargs
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        # get group nodes
        nodes, tot = self.controller.get_ssh_nodes(group_id=self.oid, filter_expired=False)
        if tot > 0:
            raise ApiManagerError('Group %s is not empty. It contains %s nodes' % (self.uuid, tot))
        # for user in users:
        #     user.delete(soft=True)

        return kvargs

    @trace(op='node-add.update')
    def add_node(self, node):
        """Add new node to group.

        :param node: sshnode id, uuid or name
        :return: node uuid
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        self.verify_permisssions('update')

        try:
            node = self.controller.get_ssh_node(node)
            self.manager.add_node_to_group(node.model, self.model)
            self.logger.debug('Add node %s to group: %s' % (node.uuid, self.uuid))
            return node.uuid
        except TransactionError as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=ex.code)
        except Exception as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=400)

    @trace(op='node-del.update')
    def remove_node(self, node):
        """Remove new node from group.

        :param node: sshnode id, uuid or name
        :return: node uuid
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        self.verify_permisssions('update')

        try:
            node = self.controller.get_ssh_node(node)
            self.manager.remove_node_from_group(node.model, self.model)
            self.logger.debug('Remove node %s from group: %s' % (node.uuid, self.uuid))
            return node.uuid
        except TransactionError as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=ex.code)
        except Exception as ex:
            self.logger.error(ex, exc_info=1)
            raise ApiManagerError(ex, code=400)


class ApiSshNode(SshApiObject):
    objdef = ApiObject.join_typedef(ApiSshGroup.objdef, 'SshNode')
    objuri = 'gas/nodes'
    objname = 'sshnode'
    objdesc = 'sshnode'

    role_templates = {
        'ApiSuperAdmin': {
            'desc': 'Super administrator. Can all',
            'name': 'ApiSuperAdminRole',
            'perms': [
                {'subsystem': 'ssh', 'type': 'SshGroup.SshNode', 'objid': '*//*', 'action': '*'},
                {'subsystem': 'ssh', 'type': 'SshGroup.SshNode.SshUser', 'objid': '*//*//*', 'action': '*'},
            ],
        }
    }
    role_templates_exclusions = ['ApiSuperAdmin']

    def __init__(self, *args, **kvargs):
        """ """
        SshApiObject.__init__(self, *args, **kvargs)

        self.node_type = None
        self.ip_address = None

        if self.model is not None:
            self.node_type = self.model.node_type
            self.ip_address = self.model.ip_address

        # child classes
        self.child_classes = [ApiSshUser]

        self.update_object = self.manager.update_ssh_node
        self.delete_object = self.manager.delete

    def info(self):
        """Get object info

        :return: Dictionary with object info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = SshApiObject.info(self)
        info.update({
            'node_type': str(self.node_type),
            'ip_address': self.ip_address
        })
        return info

    def detail(self):
        """Get object extended info

        :return: Dictionary with object detail.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = self.info()
        info['groups'] = []
        info['users'] = []
        if self.model is not None:
            for group in self.model.groups:
                info['groups'].append({'name': group.name, 'id': group.uuid})
        users, total = self.controller.manager.get_paginated_users(node_id=self.oid, with_perm_tag=False,
                                                                   filter_expired=False)
        for user in users:
            info['users'].append({'name': user.username, 'id': user.uuid, 'pwd': user.password,
                                  'key': user.key_name})
        return info

    def pre_delete(self, *args, **kvargs):
        """Pre delete function. This function is used in delete method. Extend
        this function to manipulate and validate delete input params.

        :param args: custom params
        :param kvargs: custom params
        :return: kvargs
        :raises ApiManagerError: raise :class:`ApiManagerError`
        """
        # get node users
        # users, tot = self.controller.get_ssh_users(node_id=self.oid)
        users, tot = self.manager.get_node_users(node_id=self.oid)
        for user in users:
            user = ApiSshUser(self.controller, oid=user.id, name=user.name, objid=user.objid, model=user)
            user.delete(soft=True)

        return kvargs

    @trace(op='use')
    def action(self, action, action_id, orig_params, status=None):
        """Send node action

        :param action: action name
        :param action: action id
        :param params: action params
        :param status: action status
        :return:
        """
        self.verify_permisssions('use')

        if action_id is None:
            action_id = id_gen()

        params = deepcopy(orig_params)
        params.update({
            'node_id': self.uuid,
            'node_name': self.name
        })

        # send event
        if status is None:
            status = True
        else:
            status = (False, status)

        data = {
            'opid': action_id,
            'op': action,
            'api_id': operation.id,
            'args': [],
            # 'kwargs': compat(params),
            'kwargs': json.dumps(params),
            'elapsed': params.get('elapsed', 0),
            'response': [status, '']
        }

        source = {
            'user': operation.user[0],
            'ip': operation.user[1],
            'identity': operation.user[2]
        }

        dest = {
            'ip': self.controller.module.api_manager.server_name,
            'port': self.controller.module.api_manager.http_socket,
            'objid': self.objid,
            'objtype': self.objtype,
            'objdef': self.objdef,
            'action': action
        }

        # send event
        try:
            client = self.controller.module.api_manager.event_producer
            client.send(self.SSH_OPERATION, data, source, dest)
            self.logger.debug('Send ssh node %s action %s event: %s' % (self.uuid, action, action_id))
        except Exception as ex:
            self.logger.warning('Event can not be published. Event producer is not configured - %s' % ex)
        return action_id

    #
    # authorization
    #
    def get_role_templates(self):
        res = []
        for k, v in self.role_templates.items():
            res.append({'name': k, 'desc': v.get('desc')})

        # find all node users
        node_users, tot = self.controller.get_ssh_users(node=self.oid, filter_expired=False)
        for node_user in node_users:
            for k, v in node_user.role_templates.items():
                name = k % node_user.username
                desc = v.get('desc') % node_user.username
                res.append({'name': name, 'desc': desc})

        return res

    def get_role_template_names(self):
        res = []
        for k, v in self.role_templates.items():
            res.append(k)

        # find all node users
        node_users, tot = self.controller.get_ssh_users(node=self.oid, filter_expired=False)
        for node_user in node_users:
            for k, v in node_user.role_templates.items():
                name = k % node_user.username
                res.append(name)

        for item in self.role_templates_exclusions:
            res.remove(item)

        return res

    def get_users(self):
        res = []
        try:
            self.verify_permisssions('update')

            # get auth users for node
            for tmpl, role in self.role_templates.items():
                perms = []
                for op in role.get('perms'):
                    p = deepcopy(op)
                    objid = p['objid'].replace('<objid>', self.objid)
                    perms.append('%s,%s,%s,%s' % (p['subsystem'], p['type'], objid, p['action']))
                users = self.api_client.get_perms_users(perms)
                for user in users:
                    user['role'] = tmpl
                    res.append(user)

            # auth users for node users
            node_users, tot = self.controller.get_ssh_users(node=self.oid, filter_expired=False)
            for node_user in node_users:
                for tmpl, role in node_user.role_templates.items():
                    perms = []
                    for op in role.get('perms'):
                        p = deepcopy(op)
                        objid = p['objid'].replace('<objid>', self.objid).replace('<objid2>', node_user.objid)
                        perms.append('%s,%s,%s,%s' % (p['subsystem'], p['type'], objid, p['action']))
                    users = self.api_client.get_perms_users(perms)
                    for user in users:
                        user['role'] = tmpl % node_user.username
                        res.append(user)
        except BeehiveApiClientError:
            self.logger.error('Error get %s %s users' % (self.objname, self.name), exc_info=1)
            raise ApiManagerError('Error get %s %s users' % (self.objname, self.name))
        self.logger.debug('Get %s %s users: %s' % (self.objname, self.name, truncate(users)))
        return res

    def set_user(self, user_id=None, role=None):
        try:
            self.verify_permisssions('update')

            if role not in self.get_role_template_names():
                raise ApiManagerError('Role %s not found or can not be used' % role)

            # get role and username
            role, username = role.split('.')

            # get node user
            node_users, tot = self.controller.get_ssh_users(node=self.oid, username=username, filter_expired=False)
            if tot == 0:
                raise ApiManagerError('User %s for node %s not found or you do not have privileges to see it' %
                                      (username, self.uuid))
            node_user = node_users[0]

            # get perms
            role = node_user.role_templates.get(role+'.%s')
            perms = []
            for op in role.get('perms'):
                p = deepcopy(op)
                p['objid'] = p['objid'].replace('<objid>', self.objid).replace('<objid2>', node_user.objid)
                perms.append(p)

            res = self.api_client.append_user_permissions(user_id, perms)
        except BeehiveApiClientError:
            self.logger.error('Error set %s %s users' % (self.objname, self.name), exc_info=1)
            raise ApiManagerError('Error set %s %s users' % (self.objname, self.name))
        self.logger.debug('Set %s %s users: %s' % (self.objname, self.name, res))
        return True

    def unset_user(self, user_id=None, role=None):
        try:
            self.verify_permisssions('update')

            if role not in self.get_role_template_names():
                raise ApiManagerError('Role %s not found or can not be used' % role)

            # get role and username
            role, username = role.split('.')

            # get node user
            node_users, tot = self.controller.get_ssh_users(node=self.oid, username=username, filter_expired=False)
            if tot == 0:
                raise ApiManagerError('User %s for node %s not found or you do not have privileges to see it' %
                                      (username, self.uuid))
            node_user = node_users[0]

            # get perms
            role = node_user.role_templates.get(role+'.%s')
            perms = []
            for op in role.get('perms'):
                p = deepcopy(op)
                p['objid'] = p['objid'].replace('<objid>', self.objid).replace('<objid2>', node_user.objid)
                perms.append(p)

            res = self.api_client.remove_user_permissions(user_id, perms)
        except BeehiveApiClientError:
            self.logger.error('Error unset %s %s users' % (self.objname, self.name), exc_info=1)
            raise ApiManagerError('Error unset %s %s users' % (self.objname, self.name))
        self.logger.debug('Unset %s %s users: %s' % (self.objname, self.name, res))
        return True

    def get_groups(self):
        res = []
        try:
            self.verify_permisssions('update')

            # get groups
            for tmpl, role in self.role_templates.items():
                perms = []
                for op in role.get('perms'):
                    p = deepcopy(op)
                    objid = p['objid'].replace('<objid>', self.objid)
                    perms.append('%s,%s,%s,%s' % (p['subsystem'], p['type'], objid, p['action']))
                groups = self.api_client.get_perms_groups(perms)
                for group in groups:
                    group['role'] = tmpl
                    res.append(group)

            # auth users for node users
            node_users, tot = self.controller.get_ssh_users(node=self.oid, filter_expired=False)
            for node_user in node_users:
                for tmpl, role in node_user.role_templates.items():
                    perms = []
                    for op in role.get('perms'):
                        p = deepcopy(op)
                        objid = p['objid'].replace('<objid>', self.objid).replace('<objid2>', node_user.objid)
                        perms.append('%s,%s,%s,%s' % (p['subsystem'], p['type'], objid, p['action']))
                    groups = self.api_client.get_perms_groups(perms)
                    for group in groups:
                        group['role'] = tmpl % node_user.username
                        res.append(group)
        except BeehiveApiClientError:
            self.logger.error('Error get %s %s groups' % (self.objname, self.name), exc_info=1)
            raise ApiManagerError('Error get %s %s groups' % (self.objname, self.name))
        self.logger.debug('Get %s %s groups: %s' % (self.objname, self.name, truncate(groups)))
        return res

    def set_group(self, group_id=None, role=None):
        try:
            self.verify_permisssions('update')

            if role not in self.get_role_template_names():
                raise ApiManagerError('Role %s not found or can not be used' % role)

            # get role and username
            role, username = role.split('.')

            # get node user
            node_users, tot = self.controller.get_ssh_users(node=self.oid, username=username, filter_expired=False)
            if tot == 0:
                raise ApiManagerError('User %s for node %s not found or you do not have privileges to see it' %
                                      (username, self.uuid))
            node_user = node_users[0]

            # get perms
            role = node_user.role_templates.get(role+'.%s')
            perms = []
            for op in role.get('perms'):
                p = deepcopy(op)
                p['objid'] = p['objid'].replace('<objid>', self.objid).replace('<objid2>', node_user.objid)
                perms.append(p)

            res = self.api_client.append_group_permissions(group_id, perms)
        except BeehiveApiClientError:
            self.logger.error('Error set %s %s groups' % (self.objname, self.name), exc_info=1)
            raise ApiManagerError('Error set %s %s groups' % (self.objname, self.name))
        self.logger.debug('Set %s %s groups: %s' % (self.objname, self.name, res))
        return True

    def unset_group(self, group_id=None, role=None):
        try:
            self.verify_permisssions('update')

            if role not in self.get_role_template_names():
                raise ApiManagerError('Role %s not found or can not be used' % role)

            # get role and username
            role, username = role.split('.')

            # get node user
            node_users, tot = self.controller.get_ssh_users(node=self.oid, username=username, filter_expired=False)
            if tot == 0:
                raise ApiManagerError('User %s for node %s not found or you do not have privileges to see it' %
                                      (username, self.uuid))
            node_user = node_users[0]

            # get perms
            role = node_user.role_templates.get(role+'.%s')
            perms = []
            for op in role.get('perms'):
                p = deepcopy(op)
                p['objid'] = p['objid'].replace('<objid>', self.objid).replace('<objid2>', node_user.objid)
                perms.append(p)

            res = self.api_client.remove_group_permissions(group_id, perms)
        except BeehiveApiClientError:
            self.logger.error('Error unset %s %s groups' % (self.objname, self.name), exc_info=1)
            raise ApiManagerError('Error unset %s %s groups' % (self.objname, self.name))
        self.logger.debug('Unset %s %s groups: %s' % (self.objname, self.name, res))
        return True


class ApiSshUser(SshApiObject):
    objdef = ApiObject.join_typedef(ApiSshNode.objdef, 'SshUser')
    objuri = 'gas/users'
    objname = 'sshuser'
    objdesc = 'sshuser'

    role_templates = {
        'connect.%s': {
            'desc': 'Node connect - %s. Can list node, can connect and execute command over node, '
                    'can view node actions',
            'name': 'NodeConnectRole',
            'perms': [
                {'subsystem': 'ssh', 'type': 'SshGroup.SshNode', 'objid': '<objid>', 'action': 'view'},
                {'subsystem': 'ssh', 'type': 'SshGroup.SshNode', 'objid': '<objid>', 'action': 'use'},
                {'subsystem': 'ssh', 'type': 'SshGroup.SshNode.SshUser', 'objid': '<objid2>',
                 'action': 'view'},
            ],
        },
        'viewer.%s': {
            'desc': 'Node viewer - %s. Can list node, can execute simple command over node (like show log)',
            'name': 'NodeViewerRole',
            'perms': [
                {'subsystem': 'ssh', 'type': 'SshGroup.SshNode', 'objid': '<objid>', 'action': 'view'},
                {'subsystem': 'ssh', 'type': 'SshGroup.SshNode.SshUser', 'objid': '<objid2>',
                 'action': 'view'},
            ]
        }
    }

    def __init__(self, *args, **kvargs):
        """ """
        SshApiObject.__init__(self, *args, **kvargs)

        self.username = None
        self.password = None
        self.node_id = None

        if self.model is not None:
            self.username = self.model.username
            self.password = self.model.password
            self.node_id = self.model.node_id
            self.node_name = getattr(self.model, 'node_name', None)
            self.key_id = getattr(self.model, 'key_id', None)
            self.key_name = getattr(self.model, 'key_name', None)

        # child classes
        self.child_classes = []

        self.update_object = self.manager.update_ssh_user
        self.delete_object = self.manager.delete

    def info(self):
        """Get object info

        :return: Dictionary with object info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = SshApiObject.info(self)
        info.update({
            'id': str(self.oid),
            'uuid': str(self.uuid),
            'username': str(self.username),
            'password': str(self.password),
            'node_id': self.node_id,
            'node_name': self.node_name,
            'key_id': self.key_id,
            'key_name': self.key_name
        })
        return info

    def detail(self):
        """Get object extended info

        :return: Dictionary with object detail.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = self.info()
        return info

    def get_password(self):
        """Get user password not encrypted"""
        self.verify_permisssions(action='use')

        return self.decrypt_data(str(self.password))
    
    
class ApiSshKey(SshApiObject):
    objdef = 'SshKey'
    objuri = 'gas/keys'
    objname = 'sshkey'
    objdesc = 'sshkey'

    role_templates = {
        'ApiSuperAdmin': {
            'desc': 'Super administrator. Can all',
            'name': 'ApiSuperAdminRole',
            'perms': [
                {'subsystem': 'ssh', 'type': 'SshKey', 'objid': '*', 'action': '*'}
            ],
        },
        'master': {
            'desc': 'Key owner. Can manager key',
            'name': 'KeyAdminRole',
            'perms': [
                {'subsystem': 'ssh', 'type': 'SshKey', 'objid': '<objid>', 'action': '*'}
            ]
        },
        'viewer': {
            'desc': 'Key viewer. Can list key',
            'name': 'KeyViewerRole',
            'perms': [
                {'subsystem': 'ssh', 'type': 'SshKey', 'objid': '<objid>', 'action': 'view'}
            ]
        }
    }
    role_templates_exclusions = ['ApiSuperAdmin']

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

    def info(self):
        """Get object info

        :return: Dictionary with object info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = SshApiObject.info(self)
        info.update({
            'name': str(self.name),
            'priv_key': self.priv_key,
            'pub_key': self.pub_key
        })
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
        openstack_key = kvargs.pop('openstack_key', None)
        if openstack_key is not None:
            kvargs['attribute'] = json.dumps({'openstack_name': openstack_key})

        return kvargs
