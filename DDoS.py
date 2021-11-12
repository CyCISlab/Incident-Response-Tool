from datetime import datetime


class DDoS:

    def __init__(self, ddos_count, suspicious_ips, rp_ntp, rp_dns, rp_snmp, rp_unknown, attack_flag, logs):
        self.ddos_count = ddos_count
        self.suspicious_ips = suspicious_ips
        self.rp_ntp = rp_ntp
        self.rp_dns = rp_dns
        self.rp_snmp = rp_snmp
        self.rp_unknown = rp_unknown
        self.attack_flag = attack_flag
        self.ntp_log_ddos = logs[0]
        self.dns_log_ddos = logs[1]
        self.snmp_log_ddos = logs[2]

    def ddos_detection(self, row, ip_list):
        src_ip = row[2]
        dst_ip = row[4]
        protocol = row[6]
        timestamp = row[7]
        packet_size = row[13]
        inbound = row[86]
        if protocol == "17" and inbound == "1" and not src_ip in set(ip_list) and dst_ip == ip_list[0]:
            # if protocol is UDP, packet is inbound, source ip not known and target is server ip
            if float(packet_size) == 440:
                self.ntp_detected(src_ip, timestamp)
            elif float(packet_size) > 1000:
                self.ntp_log_ddos.append(0)
                if self.attack_flag == -1:
                    # Attack not identified
                    self.unknown_detected(src_ip, timestamp)
                elif self.attack_flag == 0:
                    # dns attack
                    self.dns_detected(src_ip, timestamp)
                elif self.attack_flag == 1:
                    # snmp attack
                    self.snmp_detected(src_ip, timestamp)
            else:
                self.ntp_log_ddos.append(0)
                self.dns_log_ddos.append(0)
                self.snmp_log_ddos.append(0)
        else:
            self.ntp_log_ddos.append(0)
            self.dns_log_ddos.append(0)
            self.snmp_log_ddos.append(0)

    def ntp_detected(self, src_ip, timestamp):
        self.dns_log_ddos.append(0)
        self.snmp_log_ddos.append(0)
        if src_ip in self.rp_ntp:
            past_timestamp = self.rp_ntp[src_ip][0]
            if five_seconds_passed(timestamp, past_timestamp):
                if self.rp_ntp[src_ip][1] > 10000:
                    # If 5 seconds have passed and more than 10000 packets found
                    if src_ip in self.suspicious_ips:
                        self.suspicious_ips[src_ip] += self.rp_ntp[src_ip][1]
                        self.rp_ntp[src_ip] = [timestamp, 1]
                    else:
                        self.suspicious_ips[src_ip] = self.rp_ntp[src_ip][1]
                        self.rp_ntp[src_ip] = [timestamp, 1]
                    for pos in range(self.ddos_count, len(self.ntp_log_ddos)):
                        if self.ntp_log_ddos[pos] == -1:
                            self.ntp_log_ddos[pos] = 1
                    self.ntp_log_ddos.append(-1)
                    self.ddos_count = len(self.ntp_log_ddos) - 1
                else:
                    # If 5 seconds have passed and 10000 or less packets found, reset count
                    self.rp_ntp[src_ip] = [timestamp, 1]
                    for pos in range(self.ddos_count, len(self.ntp_log_ddos)):
                        if self.ntp_log_ddos[pos] == -1:
                            self.ntp_log_ddos[pos] = 0
                    self.ntp_log_ddos.append(-1)
                    self.ddos_count = len(self.ntp_log_ddos) - 1
            else:
                # If 5 seconds haven't passed yet, keep counting
                self.rp_ntp[src_ip][1] += 1
                self.ntp_log_ddos.append(-1)
        else:
            self.rp_ntp[src_ip] = [timestamp, 1]
            self.ntp_log_ddos.append(-1)
            self.ddos_count = len(self.ntp_log_ddos) - 1

    def dns_detected(self, src_ip, timestamp):
        self.snmp_log_ddos.append(0)
        if src_ip in self.rp_dns:
            past_timestamp = self.rp_dns[src_ip][0]
            if five_seconds_passed(timestamp, past_timestamp):
                if self.rp_dns[src_ip][1] > 10000:
                    # If 5 seconds have passed and more than 10000 packets found
                    if src_ip in self.suspicious_ips:
                        self.suspicious_ips[src_ip] += self.rp_dns[src_ip][1]
                        self.rp_dns[src_ip] = [timestamp, 1]
                    else:
                        self.suspicious_ips[src_ip] = self.rp_dns[src_ip][1]
                        self.rp_dns[src_ip] = [timestamp, 1]
                    for pos in range(self.ddos_count, len(self.dns_log_ddos)):
                        if self.dns_log_ddos[pos] == -1:
                            self.dns_log_ddos[pos] = 1
                    self.dns_log_ddos.append(-1)
                    self.ddos_count = len(self.dns_log_ddos) - 1
                else:
                    # If 5 seconds have passed and 10000 or less packets found, reset count
                    self.rp_dns[src_ip] = [timestamp, 1]
                    self.attack_flag = -1
                    for pos in range(self.ddos_count, len(self.dns_log_ddos)):
                        if self.dns_log_ddos[pos] == -1:
                            self.dns_log_ddos[pos] = 0
                    self.dns_log_ddos.append(-1)
                    self.ddos_count = len(self.dns_log_ddos) - 1
            else:
                # If 5 seconds haven't passed yet, keep counting
                self.rp_dns[src_ip][1] += 1
                self.dns_log_ddos.append(-1)
        else:
            self.rp_dns[src_ip] = [timestamp, 1]
            self.dns_log_ddos.append(-1)
            self.ddos_count = len(self.dns_log_ddos) - 1

    def snmp_detected(self, src_ip, timestamp):
        self.dns_log_ddos.append(0)
        if src_ip in self.rp_snmp:
            past_timestamp = self.rp_snmp[src_ip][0]
            if five_seconds_passed(timestamp, past_timestamp):
                if self.rp_snmp[src_ip][1] > 10000:
                    # If 5 seconds have passed and more than 10000 packets found
                    if src_ip in self.suspicious_ips:
                        self.suspicious_ips[src_ip] += self.rp_snmp[src_ip][1]
                        self.rp_snmp[src_ip] = [timestamp, 0]
                    else:
                        self.suspicious_ips[src_ip] = self.rp_snmp[src_ip][1]
                        self.rp_snmp[src_ip] = [timestamp, 0]
                    for pos in range(self.ddos_count, len(self.snmp_log_ddos)):
                        if self.snmp_log_ddos[pos] == -1:
                            self.snmp_log_ddos[pos] = 1
                    self.snmp_log_ddos.append(-1)
                    self.ddos_count = len(self.snmp_log_ddos) - 1
                else:
                    # If 5 seconds have passed and 10000 or less packets found, reset count
                    self.rp_snmp[src_ip] = [timestamp, 1]
                    self.attack_flag = -1
                    for pos in range(self.ddos_count, len(self.snmp_log_ddos)):
                        if self.snmp_log_ddos[pos] == -1:
                            self.snmp_log_ddos[pos] = 0
                    self.snmp_log_ddos.append(-1)
                    self.ddos_count = len(self.snmp_log_ddos) - 1
            else:
                # If 5 seconds haven't passed yet, keep counting
                self.rp_snmp[src_ip][1] += 1
                self.snmp_log_ddos.append(-1)
        else:
            self.rp_snmp[src_ip] = [timestamp, 1]
            self.snmp_log_ddos.append(-1)
            self.ddos_count = len(self.snmp_log_ddos) - 1

    def unknown_detected(self, src_ip, timestamp):
        if src_ip in self.rp_unknown:
            past_timestamp = self.rp_unknown[src_ip][0]
            if five_seconds_passed(timestamp, past_timestamp):
                if self.rp_unknown[src_ip][1] > 10000:
                    # If 5 seconds have passed and more than 10000 packets found
                    if src_ip in self.suspicious_ips:
                        self.suspicious_ips[src_ip] += self.rp_unknown[src_ip][1]
                        total = self.rp_unknown[src_ip][1] + self.rp_unknown[src_ip][2]
                        self.rp_unknown[src_ip] = [timestamp, 1, total]
                    else:
                        self.suspicious_ips[src_ip] = self.rp_unknown[src_ip][1]
                        total = self.rp_unknown[src_ip][1]
                        self.rp_unknown[src_ip] = [timestamp, 1, total]
                    self.dns_log_ddos.append(-1)
                    self.snmp_log_ddos.append(-1)
                else:
                    # If 5 seconds have passed and 10000 or less packets found, reset count
                    total = self.rp_unknown[src_ip][2]
                    self.rp_unknown[src_ip] = [timestamp, 1, total]
                    for pos in range(self.ddos_count, len(self.dns_log_ddos)):
                        if self.dns_log_ddos[pos] == -1:
                            self.dns_log_ddos[pos] = 0
                            self.snmp_log_ddos[pos] = 0
                    self.dns_log_ddos.append(-1)
                    self.snmp_log_ddos.append(-1)
                    self.ddos_count = len(self.dns_log_ddos) - 1
            else:
                # If 5 seconds haven't passed yet, keep counting
                self.rp_unknown[src_ip][1] += 1
                self.dns_log_ddos.append(-1)
                self.snmp_log_ddos.append(-1)
        else:
            self.rp_unknown[src_ip] = [timestamp, 1, 0]
            self.dns_log_ddos.append(-1)
            self.snmp_log_ddos.append(-1)
            self.ddos_count = len(self.dns_log_ddos) - 1

    def get_ddos_count(self):
        return self.ddos_count

    def get_suspicious_ips(self):
        return self.suspicious_ips

    def get_rp_ntp(self):
        return self.rp_ntp

    def get_rp_dns(self):
            return self.rp_dns

    def get_rp_snmp(self):
            return self.rp_snmp

    def get_rp_unknown(self):
        return self.rp_unknown

    def get_attack_flag(self):
        return self.attack_flag

    def get_ntp_log_ddos(self):
        return self.ntp_log_ddos

    def get_dns_log_ddos(self):
        return self.dns_log_ddos

    def get_snmp_log_ddos(self):
        return self.snmp_log_ddos

def five_seconds_passed(timestamp, past_timestamp):
    time_format = "%Y-%d-%m %H:%M:%S.%f"
    diff = datetime.strptime(timestamp, time_format) - datetime.strptime(past_timestamp, time_format)
    total_time = (diff.days * 24 * 60 * 60) + diff.seconds
    return total_time > 5