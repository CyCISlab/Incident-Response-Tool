import csv
import NTP, DNS, SNMP, DDoS
from tkinter import *
from tkinter import filedialog, ttk
from tkinter.ttk import Frame, Button, Label, Treeview


class Tool(Frame):

    top1_frame = None
    top2_frame = None
    btm1_frame = None
    btm2_frame = None
    tree = None

    def __init__(self):
        super().__init__()
        self.filename = ""
        self.bad_ips = []
        self.ntp_detected = None
        self.dns_detected = None
        self.snmp_detected = None
        self.attack_detected = -2
        self.ntp_log_ddos = []
        self.dns_log_ddos = []
        self.snmp_log_ddos = []
        self.init_ui()

    def init_ui(self):

        self.master.title("Cyber-Incident Response Tool")
        self.pack(fill=BOTH, expand=True)

        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self.top1_frame = LabelFrame(self)
        Label(self.top1_frame, text="Open Files\n").pack()
        Button(self.top1_frame, text="Open file", command=self.attack_check).pack()
        self.top1_frame.grid(row=0, column=0, sticky=N+S+W+E, pady=4, padx=5)

        self.top2_frame = LabelFrame(self)
        Label(self.top2_frame, text="Logs\n").pack()
        self.top2_frame.grid(row=0, column=1, sticky=N + S + W + E, pady=4, padx=5)

        self.btm1_frame = LabelFrame(self)
        self.define_tree()
        self.btm1_frame.grid(row=1, column=1, sticky=N+S+W+E, padx=5)

        self.btm2_frame = LabelFrame(self)
        Label(self.btm2_frame, text="Recommended Actions\n").pack()
        self.btm2_frame.grid(row=1, column=0, sticky=N+S+W+E, padx=5)

    def define_tree(self):
        self.tree = Treeview(self.btm1_frame)

        self.tree.tag_configure('odd', background='white')
        self.tree.tag_configure('even', background='#ececec')

        self.tree["columns"] = ("one", "two", "three")
        self.tree.column("#0", width=280, minwidth=280, stretch=NO)
        self.tree.column("one", width=90, minwidth=80, anchor=CENTER)
        self.tree.column("two", width=90, minwidth=80, anchor=CENTER)
        self.tree.column("three", width=90, minwidth=80, anchor=CENTER)
        self.tree.heading("#0", text="Indicators of Compromise", anchor=CENTER)
        self.tree.heading("one", text="DDoS NTP")
        self.tree.heading("two", text="DDoS DNS")
        self.tree.heading("three", text="DDoS SNMP")

        self.tree.insert("", "end", "1", text="Unusual Outbound Network Traffic", values=("OK", "OK", "OK"), tags="odd")
        self.tree.insert("", "end", "2", text="Anomalies in Privileged User Account Activity",
                         values=("OK", "OK", "OK"),
                         tags="even")
        self.tree.insert("", "end", "3", text="Geographical Irregularities", values=("OK", "OK", "OK"), tags="odd")
        self.tree.insert("", "end", "4", text="Log-In Red Flags", values=("OK", "OK", "OK"), tags="even")
        self.tree.insert("", "end", "5", text="Response Sizes", values=("OK", "OK", "OK"), tags="odd")
        self.tree.insert("", "end", "6", text="Large Number of Requests for the Same File", values=("OK", "OK", "OK"),
                         tags="even")
        self.tree.insert("", "end", "7", text="Mismatched Port-Application Traffic", values=("OK", "OK", "OK"),
                         tags="odd")
        self.tree.insert("", "end", "8", text="Suspicious Registry or System File Changes", values=("OK", "OK", "OK"),
                         tags="even")
        self.tree.insert("", "end", "9", text="Unusual DNS Requests", values=("OK", "OK", "OK"), tags="odd")
        self.tree.insert("", "end", "10", text="Bundles of data in the wrong place", values=("OK", "OK", "OK"),
                         tags="even")
        self.tree.insert("", "end", "11", text="Web Traffic with Unhuman Behaviour", values=("OK", "OK", "OK"),
                         tags="odd")
        self.tree.insert("", "end", "12", text="Signs of DDoS Activity", values=("OK", "OK", "OK"), tags="even")
        self.tree.pack(side=TOP, fill=BOTH, expand=True)

    def attack_check(self):
        self.filename = open_file()
        self.analysis()
        if self.ntp_detected and not self.dns_detected and not self.snmp_detected:
            #Only ntp
            self.attack_detected = 0
            self.actions()
        elif not self.ntp_detected and self.dns_detected and not self.snmp_detected:
            #Only dns
            self.attack_detected = 1
            self.actions()
        elif not self.ntp_detected and not self.dns_detected and self.snmp_detected:
            #Only snmp
            self.attack_detected = 2
            self.actions()
        elif self.ntp_detected and self.dns_detected and not self.snmp_detected:
            #ntp and dns
            self.attack_detected = 3
            self.actions()
        elif self.ntp_detected and not self.dns_detected and self.snmp_detected:
            #ntp and snmp
            self.attack_detected = 4
            self.actions()
        elif not self.ntp_detected and self.dns_detected and self.snmp_detected:
            #dns and snmp
            self.attack_detected = 5
            self.actions()
        elif self.ntp_detected and self.dns_detected and self.snmp_detected:
            #all
            self.attack_detected = 6
            self.actions()
        else:
            #No attack
            print()

    def analysis(self):
        with open(self.filename, 'r') as file:
            reader = csv.reader(file)
            step = (300 / 10000)

            def MAIN(data):
                count = 0
                ddos_count = 0
                attack_flag = -1
                suspicious_ips = {}
                ip_list = ip_list_read()
                rp_ntp, rp_dns, rp_snmp, rp_unknown = ({}, {}, {}, {})
                self.ntp_log_ddos, self.dns_log_ddos, self.snmp_log_ddos = ([], [], [])
                self.ntp_detected, self.dns_detected, self.snmp_detected = (False, False, False)
                for row in data:
                    src_port = row[3]
                    protocol = row[6]
                    packet_size = row[13]
                    inbound = row[86]
                    if NTP.ntp_check(src_port, protocol, packet_size, inbound):
                        #ntp attack
                        ntp_class = NTP.NTP(suspicious_ips, self.ntp_detected, self.ntp_log_ddos)
                        ntp_class.ntp_detection(row, ip_list)
                        suspicious_ips = ntp_class.get_suspicious_ips()
                        self.ntp_detected = ntp_class.get_ntp_detected()
                        self.ntp_log_ddos = ntp_class.get_ntp_log_ddos()
                        self.dns_log_ddos.append(0)
                        self.snmp_log_ddos.append(0)
                    elif DNS.dns_check(src_port, protocol, inbound):
                        #dns attack
                        dns_class = DNS.DNS(ddos_count, suspicious_ips, rp_dns, rp_unknown, attack_flag, self.dns_detected, self.dns_log_ddos, self.snmp_log_ddos)
                        dns_class.dns_detection(row, ip_list)
                        ddos_count = dns_class.get_ddos_count()
                        suspicious_ips = dns_class.get_suspicious_ips()
                        rp_dns = dns_class.get_rp_dns()
                        attack_flag = dns_class.get_attack_flag()
                        self.dns_detected = dns_class.get_dns_detected()
                        self.dns_log_ddos = dns_class.get_dns_log_ddos()
                        self.snmp_log_ddos = dns_class.get_snmp_log_ddos()
                        rp_unknown = dns_class.get_rp_unknown()
                        self.ntp_log_ddos.append(0)
                    elif SNMP.snmp_check(src_port, protocol, inbound):
                        #smnp attack
                        snmp_class = SNMP.SNMP(ddos_count, suspicious_ips, rp_snmp, rp_unknown, attack_flag, self.snmp_detected, self.snmp_log_ddos, self.dns_log_ddos)
                        snmp_class.snmp_detection(row, ip_list)
                        ddos_count = snmp_class.get_ddos_count()
                        suspicious_ips = snmp_class.get_suspicious_ips()
                        rp_snmp = snmp_class.get_rp_snmp()
                        attack_flag = snmp_class.get_attack_flag()
                        self.snmp_detected = snmp_class.get_snmp_detected()
                        self.snmp_log_ddos = snmp_class.get_snmp_log_ddos()
                        self.dns_log_ddos = snmp_class.get_dns_log_ddos()
                        rp_unknown = snmp_class.get_rp_unknown()
                        self.ntp_log_ddos.append(0)
                    else:
                        logs = [self.ntp_log_ddos, self.dns_log_ddos, self.snmp_log_ddos]
                        ddos_class = DDoS.DDoS(ddos_count, suspicious_ips, rp_ntp, rp_dns, rp_snmp, rp_unknown, attack_flag, logs)
                        ddos_class.ddos_detection(row, ip_list)
                        ddos_count = ddos_class.get_ddos_count()
                        suspicious_ips = ddos_class.get_suspicious_ips()
                        rp_ntp = ddos_class.get_rp_ntp()
                        rp_dns = ddos_class.get_rp_dns()
                        rp_snmp = ddos_class.get_rp_snmp()
                        rp_unknown = ddos_class.get_rp_unknown()
                        attack_flag = ddos_class.get_attack_flag()
                        self.ntp_log_ddos = ddos_class.get_ntp_log_ddos()
                        self.dns_log_ddos = ddos_class.get_dns_log_ddos()
                        self.snmp_log_ddos = ddos_class.get_snmp_log_ddos()
                    count += 1
                    if count % 19 == 0:
                        progress.step(step)
                        progress.update()

                self.bad_ips = []
                for ip in suspicious_ips:
                    self.bad_ips.append(ip)

            loading = Label(self.top1_frame, text="Loading file...")
            progress = ttk.Progressbar(self.top1_frame, length=300, mode="indeterminate")
            loading.pack()
            progress.pack()

            progress.after(1, MAIN(reader))

            loading.pack_forget()
            progress.destroy()

    def actions(self):
        if self.attack_detected == 0:
            #ntp
            self.tree.set("5", 0, "!!!!!")
            self.tree.set("7", 0, "!!!!!")
            self.tree.set("12", 0, "!!!!!")

            Label(self.top2_frame, text="An ip address not belonging to the network was found. It has been listed as a precaution.\n").pack()
            Label(self.top2_frame, text="Packets of length 440 have been found. This is the usual length of a packet of a NTP attack.\n").pack()
            Label(self.top2_frame, text="Suspicious ip address has been been found sending data from unusual ports.\n").pack()
            Label(self.top2_frame, text="The same ip address has sent several similar responses to the server. This is an indicator of DDoS activity.\n").pack()

            actions_file = open("NTP_actions.txt", "r")

            for row in actions_file:
                Label(self.btm2_frame, text=row.strip("\n")).pack()
        elif self.attack_detected in [1, 2, 5]:
            #dns, snmp or dns and snmp
            Label(self.top2_frame, text="An ip address not belonging to the network was found. It has been listed as a precaution.\n").pack()
            Label(self.top2_frame, text="Large packets have been found being sent to the server.\n").pack()
            Label(self.top2_frame, text="Suspicious ip address has been been found sending data from unusual ports.\n").pack()
            Label(self.top2_frame, text="The same ip address has sent several similar responses to the server. This is an indicator of DDoS activity.\n").pack()

            if self.attack_detected == 1:
                #dns
                self.tree.set("5", 1, "!!!!!")
                self.tree.set("7", 1, "!!!!!")
                self.tree.set("12", 1, "!!!!!")

                actions_file = open("DNS_actions.txt", "r")

                for row in actions_file:
                    Label(self.btm2_frame, text=row.strip("\n")).pack()
            elif self.attack_detected == 2:
                #snmp
                self.tree.set("5", 2, "!!!!!")
                self.tree.set("7", 2, "!!!!!")
                self.tree.set("12", 2, "!!!!!")

                actions_file = open("SNMP_actions.txt", "r")

                for row in actions_file:
                    Label(self.btm2_frame, text=row.strip("\n")).pack()
            else:
                #dns and snmp
                self.tree.set("5", 1, "!!!!!")
                self.tree.set("7", 1, "!!!!!")
                self.tree.set("12", 1, "!!!!!")
                self.tree.set("5", 2, "!!!!!")
                self.tree.set("7", 2, "!!!!!")
                self.tree.set("12", 2, "!!!!!")

                actions_file = open("DNS_actions.txt", "r")

                for row in actions_file:
                    Label(self.btm2_frame, text=row.strip("\n")).pack()

                actions_file = open("SNMP_actions.txt", "r")

                for row in actions_file:
                    Label(self.btm2_frame, text=row.strip("\n")).pack()
        elif self.attack_detected in [3, 4, 6]:
            #ntp and dns, ntp and snmp or all 3 attacks
            Label(self.top2_frame, text="An ip address not belonging to the network was found. It has been listed as a precaution.\n").pack()
            Label(self.top2_frame, text="Packets of length 440 have been found. This is the usual length of a packet of a NTP attack.\n").pack()
            Label(self.top2_frame, text="Large packets have been found being sent to the server.\n").pack()
            Label(self.top2_frame, text="Suspicious ip address has been been found sending data from unusual ports.\n").pack()
            Label(self.top2_frame, text="The same ip address has sent several similar responses to the server. This is an indicator of DDoS activity.\n").pack()

            if self.attack_detected == 3:
                #ntp and dns
                self.tree.set("5", 0, "!!!!!")
                self.tree.set("7", 0, "!!!!!")
                self.tree.set("12", 0, "!!!!!")
                self.tree.set("5", 1, "!!!!!")
                self.tree.set("7", 1, "!!!!!")
                self.tree.set("12", 1, "!!!!!")

                actions_file = open("NTP_actions.txt", "r")

                for row in actions_file:
                    Label(self.btm2_frame, text=row.strip("\n")).pack()

                actions_file = open("DNS_actions.txt", "r")

                for row in actions_file:
                    Label(self.btm2_frame, text=row.strip("\n")).pack()
            elif self.attack_detected == 4:
                #ntp and snmp
                self.tree.set("5", 0, "!!!!!")
                self.tree.set("7", 0, "!!!!!")
                self.tree.set("12", 0, "!!!!!")
                self.tree.set("5", 2, "!!!!!")
                self.tree.set("7", 2, "!!!!!")
                self.tree.set("12", 2, "!!!!!")

                actions_file = open("NTP_actions.txt", "r")

                for row in actions_file:
                    Label(self.btm2_frame, text=row.strip("\n")).pack()

                actions_file = open("SNMP_actions.txt", "r")

                for row in actions_file:
                    Label(self.btm2_frame, text=row.strip("\n")).pack()
            else:
                #all 3 attacks
                self.tree.set("5", 0, "!!!!!")
                self.tree.set("7", 0, "!!!!!")
                self.tree.set("12", 0, "!!!!!")
                self.tree.set("5", 1, "!!!!!")
                self.tree.set("7", 1, "!!!!!")
                self.tree.set("12", 1, "!!!!!")
                self.tree.set("5", 2, "!!!!!")
                self.tree.set("7", 2, "!!!!!")
                self.tree.set("12", 2, "!!!!!")

                actions_file = open("NTP_actions.txt", "r")

                for row in actions_file:
                    Label(self.btm2_frame, text=row.strip("\n")).pack()

                actions_file = open("DNS_actions.txt", "r")

                for row in actions_file:
                    Label(self.btm2_frame, text=row.strip("\n")).pack()

                actions_file = open("SNMP_actions.txt", "r")

                for row in actions_file:
                    Label(self.btm2_frame, text=row.strip("\n")).pack()
        button = Button(self.top2_frame, text="Download logs")
        button["command"] = lambda: self.dwnld_logs(button)
        button.pack()

    def dwnld_logs(self, button):
        directory = filedialog.askdirectory()
        button.pack_forget()
        with open(self.filename, 'r') as file:
            reader = csv.reader(file)
            step = (300 / 10000)

            def MAIN(data):
                count = 0
                if self.attack_detected in [0, 3, 4, 6]:
                    ntp_all_logs = open(directory + "/NTP_logs_all.csv", "w", newline='')
                    ntp_size_logs = open(directory + "/NTP_logs_packet_size.csv", "w", newline='')
                    ntp_ports_logs = open(directory + "/NTP_logs_ports.csv", "w", newline='')
                    ntp_ddos_logs = open(directory + "/NTP_logs_ddos.csv", "w", newline='')
                    ntp_writer_all = csv.writer(ntp_all_logs)
                    ntp_writer_size = csv.writer(ntp_size_logs)
                    ntp_writer_ports = csv.writer(ntp_ports_logs)
                    ntp_writer_ddos = csv.writer(ntp_ddos_logs)
                if self.attack_detected in [1, 3, 5, 6]:
                    dns_all_logs = open(directory + "/DNS_logs_all.csv", "w", newline='')
                    dns_size_logs = open(directory + "/DNS_logs_packet_size.csv", "w", newline='')
                    dns_ports_logs = open(directory + "/DNS_logs_ports.csv", "w", newline='')
                    dns_ddos_logs = open(directory + "/DNS_logs_ddos.csv", "w", newline='')
                    dns_writer_all = csv.writer(dns_all_logs)
                    dns_writer_size = csv.writer(dns_size_logs)
                    dns_writer_ports = csv.writer(dns_ports_logs)
                    dns_writer_ddos = csv.writer(dns_ddos_logs)
                if self.attack_detected in [2, 4, 5, 6]:
                    snmp_all_logs = open(directory + "/SNMP_logs_all.csv", "w", newline='')
                    snmp_size_logs = open(directory + "/SNMP_logs_packet_size.csv", "w", newline='')
                    snmp_ports_logs = open(directory + "/SNMP_logs_ports.csv", "w", newline='')
                    snmp_ddos_logs = open(directory + "/SNMP_logs_ddos.csv", "w", newline='')
                    snmp_writer_all = csv.writer(snmp_all_logs)
                    snmp_writer_size = csv.writer(snmp_size_logs)
                    snmp_writer_ports = csv.writer(snmp_ports_logs)
                    snmp_writer_ddos = csv.writer(snmp_ddos_logs)
                first_line = True
                for row in data:
                    src_ip = row[2]
                    dst_ip = row[4]
                    src_port = row[3]
                    packet_size = row[13]
                    if self.attack_detected in [0, 3, 4, 6]:
                        # ntp
                        if (src_ip in set(self.bad_ips)) or (dst_ip in set(self.bad_ips)):
                            ntp_writer_all.writerow(row)
                            if float(packet_size) == 440:
                                ntp_writer_size.writerow(row)
                            if int(src_port) >= 1023:
                                ntp_writer_ports.writerow(row)
                            if self.ntp_log_ddos[count] == 1:
                                ntp_writer_ddos.writerow(row)
                        elif first_line:
                            ntp_writer_all.writerow(row)
                            ntp_writer_size.writerow(row)
                            ntp_writer_ports.writerow(row)
                            ntp_writer_ddos.writerow(row)
                    if self.attack_detected in [1, 3, 5, 6]:
                        # dns
                        if (src_ip in set(self.bad_ips)) or (dst_ip in set(self.bad_ips)):
                            dns_writer_all.writerow(row)
                            if float(packet_size) > 1000:
                                dns_writer_size.writerow(row)
                            if int(src_port) >= 1023:
                                dns_writer_ports.writerow(row)
                            if self.dns_log_ddos[count] == 1:
                                dns_writer_ddos.writerow(row)
                        elif first_line:
                            dns_writer_all.writerow(row)
                            dns_writer_size.writerow(row)
                            dns_writer_ports.writerow(row)
                            dns_writer_ddos.writerow(row)
                    if self.attack_detected in [2, 4, 5, 6]:
                        # snmp
                        if (src_ip in set(self.bad_ips)) or (dst_ip in set(self.bad_ips)):
                            snmp_writer_all.writerow(row)
                            if float(packet_size) > 1000:
                                snmp_writer_size.writerow(row)
                            if int(src_port) >= 1023:
                                snmp_writer_ports.writerow(row)
                            if self.snmp_log_ddos[count] == 1:
                                snmp_writer_ddos.writerow(row)
                        elif first_line:
                            snmp_writer_all.writerow(row)
                            snmp_writer_size.writerow(row)
                            snmp_writer_ports.writerow(row)
                            snmp_writer_ddos.writerow(row)
                    first_line = False
                    count += 1
                    if count % 19 == 0:
                        progress.step(step)
                        progress.update()
                if self.attack_detected in [0, 3, 4, 6]:
                    # ntp
                    ntp_all_logs.close()
                    ntp_size_logs.close()
                    ntp_ports_logs.close()
                    ntp_ddos_logs.close()
                if self.attack_detected in [1, 3, 5, 6]:
                    # dns
                    dns_all_logs.close()
                    dns_size_logs.close()
                    dns_ports_logs.close()
                    dns_ddos_logs.close()
                if self.attack_detected in [2, 4, 5, 6]:
                    # snmp
                    snmp_all_logs.close()
                    snmp_size_logs.close()
                    snmp_ports_logs.close()
                    snmp_ddos_logs.close()

            loading = Label(self.top2_frame, text="Creating files...")
            progress = ttk.Progressbar(self.top2_frame, length=300, mode="indeterminate")
            loading.pack()
            progress.pack()

            progress.after(1, MAIN(reader))

            loading.pack_forget()
            progress.destroy()
            button.pack()

def open_file():
    filename = filedialog.askopenfilename(
        initialdir="",
        title="Select file",
        filetypes=(("csv files", "*.csv"), ("all files", "*.*")))
    return filename

def ip_list_read():
    file = open('ip_list.txt', 'r')
    ip_list = []
    for ip in file:
        ip_list.append(ip.strip("\n"))
    return ip_list


def main():
    root = Tk()
    w = 1000  #width window
    h = 500  #height window

    ws = root.winfo_screenwidth()  # width screen
    hs = root.winfo_screenheight()  # height screen

    # x and y coordinates of window
    x = (ws / 2) - (w / 2)
    y = (hs / 2) - (h / 2)

    root.geometry('%dx%d+%d+%d' % (w, h, x, y))
    Tool()
    root.mainloop()




if __name__ == '__main__':
    main()
