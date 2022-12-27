# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2022 CSI-Piemonte

__version__ = '1.5.0'

import os.path
version_file = os.path.join(os.path.abspath(__file__).rstrip('__init__.pyc'), 'VERSION')
if os.path.isfile(version_file):
    with open(version_file) as version_file:
        __version__ = '%s-%s' % (__version__, version_file.read().strip()[:10])