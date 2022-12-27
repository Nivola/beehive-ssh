# Changelog

## Version 1.11.0 (oct 11, 2022)
* Various bugfixes

## Version 1.5.1 (Feb 11, 2022)

* Added ...
* Fixed ...
* Integrated ...
* Various bugfixes
    * correct bug in ssh user get. Some fields are not valorized
    * correct bug in list ssh user by node. Read param node in place of node_id 
    * correct bug in node user auth. User assigned is wrong because user filter by node pass a wrong parameter

## Version 1.5.0 (Jun 11, 2021)

* Added ...
* Fixed ...
* Integrated ...
    * update node ssh dynamic ansible inventory
* Various bugfixes
    * correct bug in ssh node update. Some fields are required

## Version 1.4.0 (Feb 05, 2021)

* Added ...
* Fixed ...
    * add new api ping (with sql check), capabilities and version to /v1.0/gas
* Integrated ...
* Various bugfixes

## Version 1.3.0 (Jun 21, 2020)

* Added ...
* Fixed ...
    * porting of all code to python 3
* Integrated ...
* Various bugfixes

## Version 1.2.0 (Sep 04, 2019)

* Added ...
* Fixed ...
  * modify add_ssh_user to manage user with key_oid=None
* Integrated ...
  * added master role for ssh key
  * changed put sshkey api to set openstack key name reference
* Various bugfixes

## Version 1.1.0 (May 24, 2019)

* Added ...
* Fixed ...
* Integrated ...
* Various bugfixes
  * increase to 200 size of the field name of the ssh node

## Version 1.0.0 (July 31, 2018)

First production preview release.

## Version 0.1.0 (April 18, 2016)

First private preview release.