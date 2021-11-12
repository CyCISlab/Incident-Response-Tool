class SNMP:

    def __init__(self, ddos_count, suspicious_ips, rp_snmp, rp_unknown, attack_flag, snmp_detected, snmp_log_ddos, dns_log_ddos):
        self.ddos_count = ddos_count
        self.suspicious_ips = suspicious_ips
        self.rp_snmp = rp_snmp
        self.rp_unknown = rp_unknown
        self.attack_flag = attack_flag
        self.snmp_detected = snmp_detected
        self.dns_log_ddos = dns_log_ddos
        self.snmp_log_ddos = snmp_log_ddos

    def snmp_detection(self, row, ip_list):
        src_ip = row[2]
        dst_ip = row[4]
        if not src_ip in set(ip_list) and dst_ip == ip_list[0]:
            # If source ip not known and target is server ip
            self.snmp_detected = True
            if self.attack_flag == -1:
                self.attack_flag = 1
                self.rp_snmp[src_ip] = self.rp_unknown[src_ip][0:2]
                del self.rp_unknown[src_ip]
                for pos in range(self.ddos_count, len(self.snmp_log_ddos)):
                    if self.snmp_log_ddos[pos] == -1:
                        self.dns_log_ddos[pos] = 0
                        self.snmp_log_ddos[pos] = 1
                self.ddos_count = len(self.snmp_log_ddos)
            else:
                if src_ip in self.suspicious_ips:
                    self.suspicious_ips[src_ip] += 1
                    self.rp_snmp[src_ip][1] += 1
                else:
                    self.suspicious_ips[src_ip] = 1
                    self.rp_snmp[src_ip][1] += 1
            self.snmp_log_ddos.append(-1)
        else:
            self.snmp_log_ddos.append(0)
        self.dns_log_ddos.append(0)

    def get_ddos_count(self):
        return self.ddos_count

    def get_suspicious_ips(self):
        return self.suspicious_ips

    def get_rp_snmp(self):
        return self.rp_snmp

    def get_rp_unknown(self):
        return self.rp_unknown

    def get_attack_flag(self):
        return self.attack_flag

    def get_snmp_detected(self):
        return self.snmp_detected

    def get_dns_log_ddos(self):
        return self.dns_log_ddos

    def get_snmp_log_ddos(self):
        return self.snmp_log_ddos

def snmp_check(src_port, protocol, inbound):
    return protocol == "17" and src_port == "161" and inbound == "1"