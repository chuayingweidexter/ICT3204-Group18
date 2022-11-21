import json


class Cleaner(object):
    """
    Cleaner Class for Logs Cleaning by parsing data into Pandas for data cleaning
    """

    def __init__(self, file_name) -> None:
        raw_list = list()
        with open(file_name, "r") as in_file:
            for line in in_file:
                raw_list.append(json.loads(line))

        self.sorted_raw_list: list = sorted(raw_list, key=lambda x: x["@timestamp"])

    def clean_filebeat(self, end_line_number, start_line_number=0) -> list:
        """
        Choose end timestamp and loop till that timestamp
        """
        return self.sorted_raw_list[start_line_number:end_line_number]

    def filter_tshark_field(self, field_name) -> list:
        """
        Filter Tshark logs by the field name
        """
        return [
            rawdata
            for rawdata in self.sorted_raw_list
            if rawdata["agent"]["name"] == field_name
        ]

    ## Chin Clement
    ## Initital Access (TA0001) - External Remote Services (T1133)
    def external_remote_service(self) -> list:
        """
        Cleaning of logs for External Remote Services (Initial Access)
            Using sensor: `filebeat`
            Query[filebeat] -> process.name : "ocserv" and message : "100.64.19.103"
        """

        return self.clean_filebeat(start_line_number=0, end_line_number=251)

    ## Daniel Tan ZhongHao
    ## Discovery (TA0007) - Network Share Discovery (T1135)
    def network_share_discovery(self) -> list:
        """
        Cleaning of logs for Network Share Discovery (Discovery)
            Using sensor: `tshark`
            Query[tshark] -> layers.ip.ip_ip_src : "10.32.4.176" and layers.tcp.tcp_tcp_dstport : 445
        """
        return self.filter_tshark_field("files.corp.grab.com")

    ## Gerald Peh Wei Xiang
    ## Collection (TA0009) - Data from Network Shared Drive (T1039)
    def data_from_samba(self) -> list:
        """
        Cleaning of logs for Data from Network Shared Drive (Collection)
            Using sensor: `filebeat`
            Query[filebeat] -> agent.name : "files.corp.grab.com" and process.name : "smbd_audit" and message : "10.32.4.176"
        """
        return self.clean_filebeat(start_line_number=251, end_line_number=368)

    ## Ho Xiuqi
    ## Discovery (TA0007) - Remote System Discovery (T1018)
    def remote_system_discovery(self) -> list:
        """
        Cleaning of logs for Remote System Discovery (Discovery)
            Using sensor: `filebeat`
            Query[filebeat] -> agent.name : "web.corp.grab.com" and process.name : *sshd* and message : *
        """
        return self.clean_filebeat(start_line_number=368, end_line_number=399)

    ## Lim Zhao Xiang
    ## Privilege Escalation (TA0004) - Abuse Elevation Control Mechanism: Sudo and Sudo Caching (T1548.003)
    def abuse_elevation_control(self) -> list:
        """
        Cleaning of logs for Abuse Elevation Control Mechanism: Sudo and Sudo Caching
            Using sensor: `filebeat`
            Query[filebeat] -> agent.name : "web.corp.grab.com" and process.name : "/usr/bin/bash [sshd]"
        """
        return self.clean_filebeat(start_line_number=399, end_line_number=496)

    ## Tan Zhao Yea
    ## Collection (TA0009) - Data Staged: Remote Data Staging (T1074.002)
    def remote_data_staging(self) -> list:
        """
        Cleaning of logs for Data Staged: Remote Data Staging (Collection)
            Using sensor: `filebeat`
            Query[filebeat] -> message : "grabadmin" or message : "grabdba"
        """
        return self.clean_filebeat(start_line_number=496, end_line_number=554)
