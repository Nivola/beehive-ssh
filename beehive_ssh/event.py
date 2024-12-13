# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte

import logging
from datetime import datetime
from beecell.logger import LoggerHelper
from beecell.simple import format_date
from beehive.common.event import EventHandler


class CliEventHandler(EventHandler):
    def __init__(self, api_manager):
        EventHandler.__init__(self, api_manager)

        params = self.api_manager.params

        # internal logger
        self.logger2 = logging.getLogger("CliEventHandler")
        log_path = "/var/log/%s/%s" % (params["api_package"], params["api_env"])
        logname = "%s/cli" % log_path
        logger_file = "%s.log" % logname
        loggers = [self.logger2]
        LoggerHelper.rotatingfile_handler(loggers, logging.INFO, logger_file, frmt="%(message)s")

    def callback(self, event, message):
        """Consume event relative to api where new access token is requested

        :param event:
        :param message:
        :return:
        """
        event_type = event.get("type")
        if event_type == "SSH":
            data = event.get("data")
            params = data.get("params", {})
            status = data.get("response", None)
            source = event.get("source")
            if status is True:
                status = "OK"
            else:
                msg = ""
                if isinstance(status, list):
                    msg = " - %s" % status[1]
                status = "KO" + msg

            tmpl = (
                '%(ip)s - %(user)s - %(identity)s [%(timestamp)s] "%(action_id)s %(action)s" %(elapsed)s '
                "%(node_id)s %(node_name)s %(node_user)s %(status)s"
            )
            log = {
                "timestamp": format_date(datetime.fromtimestamp(event.get("creation"))),
                "ip": source.get("ip"),
                "user": source.get("user"),
                "identity": source.get("identity"),
                "action_id": data.get("opid", None),
                "action": data.get("op", None),
                "elapsed": data.get("elapsed", None),
                "node_id": params.get("node_id", None),
                "node_name": params.get("node_name", None),
                "node_user": params.get("user", {}).get("name"),
                "status": status,
            }
            self.logger2.info(tmpl % log)
