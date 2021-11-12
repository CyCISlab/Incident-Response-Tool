class DNS:

    def __init__(self, ddos_count, suspicious_ips, rp_dns, rp_unknown, attack_flag, dns_detected, dns_log_ddos, snmp_log_ddos):
        self.ddos_count = ddos_count
        self.suspicious_ips = suspicious_ips
        self.rp_dns = rp_dns
        self.rp_unknown = rp_unknown
        self.attack_flag = attack_flag
        self.dns_detected = dns_detected
        self.dns_log_ddos = dns_log_ddos
        self.snmp_log_ddos = snmp_log_ddos

    def dns_detection(self, row, ip_list):
        src_ip = row[2]
        dst_ip = row[4]
        if not src_ip in set(ip_list) and dst_ip == ip_list[0]:
            #If source ip not known and target is server ip
            self.dns_detected = True
            if self.attack_flag == -1:
                self.attack_flag = 1
                self.rp_dns[src_ip] = self.rp_unknown[src_ip][0:2]
                del self.rp_unknown[src_ip]
                for pos in range(self.ddos_count, len(self.dns_log_ddos)):
                    if self.dns_log_ddos[pos] == -1:
                        self.dns_log_ddos[pos] = 1
                        self.snmp_log_ddos[pos] = 0
                self.ddos_count = len(self.dns_log_ddos)
            else:
                if src_ip in self.suspicious_ips:
                    self.suspicious_ips[src_ip] += 1
                    self.rp_dns[src_ip][1] += 1
                else:
                    self.suspicious_ips[src_ip] = 1
                    self.rp_dns[src_ip][1] += 1
            self.dns_log_ddos.append(-1)
        else:
            self.dns_log_ddos.append(0)
        self.snmp_log_ddos.append(0)

    def get_ddos_count(self):
        return self.ddos_count

    def get_suspicious_ips(self):
        return self.suspicious_ips

    def get_rp_dns(self):
        return self.rp_dns

    def get_rp_unknown(self):
        return self.rp_unknown

    def get_attack_flag(self):
        return self.attack_flag

    def get_dns_detected(self):
        return self.dns_detected

    def get_dns_log_ddos(self):
        return self.dns_log_ddos

    def get_snmp_log_ddos(self):
        return self.snmp_log_ddos

def dns_check(src_port, protocol, inbound):
        return protocol == "17" and src_port == "53" and inbound == "1"