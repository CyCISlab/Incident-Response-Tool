class NTP:

    def __init__(self, suspicious_ips, ntp_detected, ntp_log_ddos):
        self.suspicious_ips = suspicious_ips
        self.ntp_detected = ntp_detected
        self.ntp_log_ddos = ntp_log_ddos

    def ntp_detection(self, row, ip_list):
        src_ip = row[2]
        dst_ip = row[4]
        if not src_ip in set(ip_list) and dst_ip == ip_list[0]:
            #If source ip not known and target is server ip
            self.ntp_detected = True
            self.ntp_log_ddos.append(1)
            if src_ip in self.suspicious_ips:
                self.suspicious_ips[src_ip] += 1
            else:
                self.suspicious_ips[src_ip] = 1
        else:
            self.ntp_log_ddos.append(0)

    def get_suspicious_ips(self):
        return self.suspicious_ips

    def get_ntp_detected(self):
        return self.ntp_detected

    def get_ntp_log_ddos(self):
        return self.ntp_log_ddos

def ntp_check(src_port, protocol, packet_size, inbound):
    return protocol == "17" and src_port == "123" and packet_size == "440.0" and inbound == "1"