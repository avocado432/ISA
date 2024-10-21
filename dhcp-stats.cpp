//Author: Tereza Lapčíková, xlapci03

#include <stdio.h>
#include <string>
#include <vector>
#include <cstring>
#include <cmath>
#include <arpa/inet.h>
#include <stdlib.h>
#include <iostream>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sstream>
#include <map>
#include <syslog.h>
#include <curses.h>
#include <unistd.h>
#include <algorithm>

std::string file_name;
std::string interface_name;
std::vector<std::string> ip_prefix;
std::map<std::string, unsigned long int> max_hosts;
std::map<std::string, std::vector<std::string>> assigned_ips;
std::map<std::string, bool> is_fifty;
std::vector<std::string> requested_ips;

// function parsing input arguments
int parse_args(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        //file name
        if (strcmp(argv[i], "-r") == 0) {
            if (i+1 >= argc) {
                std::cerr<<"Error! File name is not provided.\n";
                return 1;                
            }
            if (!file_name.empty()) {
                std::cerr<<"Error! File name can only be assgined once.\n";
                return 1;
            }
            file_name = argv[i+1];
            i++;
        }
        //interface name
        else if (strcmp(argv[i], "-i") == 0) {
            if (i+1 >= argc) {
                std::cerr<<"Error! Interface name is not provided.\n";
                return 1;                
            }
            if (!interface_name.empty()) {
                std::cerr<<"Error! Interface name can only be assgined once.\n";
                return 1;
            }
            interface_name = argv[i+1];
            i++;
        }
        else{ //checking the right format of IP adresses
            std::string delimiter = "/";
            std::string arg = argv[i];
            const long unsigned int delimiter_position = arg.find(delimiter);
            if (delimiter_position == std::string::npos) {
                std::cerr<<"Error! Unknown argument (maybe invalid IP address).\n";
                return 1;
            }
            else {
                unsigned char buf[sizeof(struct in_addr)];
                std::string sub1 = arg.substr(0,delimiter_position);
                std::string sub2 = arg.substr(delimiter_position+1);
                if (inet_pton(AF_INET, sub1.c_str(),buf)) {
                    ip_prefix.push_back(argv[i]);
                }
                else {
                    std::cerr<<"Error! Unknown argument (maybe invalid IP address).\n";
                    return 1;
                }
                try {
                    if (std::stoi(sub2) > 32 || std::stoi(sub2) < 0) {
                        std::cerr<<"Error! Invalid number of net mask.\n";
                        return 1;
                    }
                }
                catch (...) { //exception handling
                    std::cerr<<"Error! Invalid net mask (not a number).\n";
                    return 1;
                }
            }            
        }
    }
    //missing input parameter file name or interface name
    if (file_name.empty() && interface_name.empty()) {
        std::cerr<<"Error! Missing parameters (-r or -i).\n";
        return 1;
    }

    return 0;
}

//create subnet mask from length of subnet
//inspired by: https://stackoverflow.com/questions/34072299/generating-a-subnet-mask-from-a-subnet-and-address-prefix-length
uint32_t create_subnet_mask (int prefix_len) {
    return prefix_len ? ~0 << (32-prefix_len) : 0;
}

//funtion to writeout the statistics using ncurses
void writeout_stats() {
    clear();
    printw("IP-Prefix Max-hosts Allocated-addresses Utilization\n");
    std::vector<std::string>::iterator iter = ip_prefix.begin();
    for (;iter != ip_prefix.end();iter++) {
        float utilization = ((float)assigned_ips[*iter].size()/ (float)max_hosts[*iter])*100;
        int allocated_addr = assigned_ips[*iter].size();
        if (max_hosts[*iter] == 0) {
            allocated_addr = 0;
            utilization = 100.0;
        }
        utilization = utilization <= 100.0 ? ( utilization >= 0 ? utilization : 0 ) : 100;
        printw("%s %lu %d %.2f%\n", (*iter).c_str(), max_hosts[*iter], allocated_addr, utilization);
        refresh();
        //case when 50% of addresses are allocated -> syslog
        if (utilization > 50.0 && is_fifty[*iter] == false) {
            syslog(LOG_INFO, "prefix %s exceeded 50%% of allocations.", (*iter).c_str());
            is_fifty[*iter] = true;
        }
        else if (is_fifty[*iter] == true && utilization <= 50.0) {
            is_fifty[*iter] = false;
        }
    }
}

//function handling dhcpacknowledge packet
void handle_acknowledge(const u_char *dhcp_packet) {
    int offset = 4*4;
    std::stringstream ss;
    for (int i = 0; i < 4; i++) {
        ss<<std::to_string(dhcp_packet[offset+i]);
        if (i < 3) {
            ss<<".";
        }
    }
    std::string client_ip_str = ss.str();
    std::vector<std::string>::iterator it = std::find(requested_ips.begin(), requested_ips.end(), client_ip_str);
    if (it != requested_ips.end()) {
        uint32_t client_ip = ntohl(inet_addr(client_ip_str.c_str()));
        std::vector<std::string>::iterator iter = ip_prefix.begin();
        for (; iter < ip_prefix.end(); iter++) {
            std::string subnet_ip_str = (*iter).substr(0,(*iter).find("/"));
            int prefix_len = stoi((*iter).substr((*iter).find("/")+1));
            uint32_t subnet_mask = create_subnet_mask(prefix_len);
            uint32_t subnet_ip = ntohl(inet_addr(subnet_ip_str.c_str()));
            //checks if IP address is in range/subnet
            //inspired by: https://stackoverflow.com/questions/31040208/standard-safe-way-to-check-if-ip-address-is-in-range-subnet
            if ((subnet_ip & subnet_mask) == (client_ip & subnet_mask)) {
                assigned_ips[*iter].push_back(client_ip_str);
                writeout_stats();
            }
        }
        requested_ips.erase(it);
    }
}

//packet handling routine
//inspired by: https://elf11.github.io/2017/01/22/libpcap-in-C.html
void ph_routine(u_char *user, const struct pcap_pkthdr *packet_handler, const u_char *packet_data) {
    const struct ether_header* ethernet_header;
    const struct ip* ip_header;
    const struct udphdr* udp_header;
    char source_ip[INET_ADDRSTRLEN];
    char destination_ip[INET_ADDRSTRLEN];
    u_int source_port, destination_port;

    ethernet_header = (struct ether_header*)packet_data;
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (struct ip*)(packet_data + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst),destination_ip, INET_ADDRSTRLEN);
        if (ip_header->ip_p == IPPROTO_UDP) {
            udp_header = (struct udphdr*)(packet_data + sizeof(struct ip) + sizeof(struct ether_header));
            source_port = ntohs(udp_header->source);
            destination_port = ntohs(udp_header->dest);
            int header_offset = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr);
            //catching outcoming packets (offer and acknowledge)
            if (source_port == 67 && destination_port == 68) {
                //dhcp option 53 is message type, value 5 is dhcpacknowladge
                for (int i = 282; packet_data[i] != 0xff; i++) {
                    if (packet_data[i] == 53) {
                        if (packet_data[i+2] == 5) {
                            handle_acknowledge(packet_data+header_offset);
                            break; //we got what we wanted, no need to continue
                        }
                        i += 2;
                    }
                    //skipping the pad option (0)
                    else if (packet_data[i] == 0) {
                        continue;
                    }
                    else {
                        i += int(packet_data[i+1]) + 1;
                    }
                }
            }
            //catching incoming packets (discover and request)
            else if (source_port == 68 && destination_port == 67) {
                bool is_request = false;
                bool recieved_ip = false;
                std::string requested_ip_str;
                for (int i = header_offset+240; packet_data[i] != 0xff; i++) {
                    //dhcp option 53 is message type, value 3 is dhcpqrequest
                    if (packet_data[i] == 53) {
                        if (packet_data[i+2] == 3) {
                            is_request = true;
                        }
                        i+=2;
                    }
                    //option 50 is requested IP address
                    else if (packet_data[i] == 50) {
                        recieved_ip = true;
                        std::stringstream ss;
                        for (int j = 0; j < 4; j++) {
                            ss<<std::to_string(packet_data[i+j+2]);
                            if (j < 3) {
                                ss<<".";
                            }
                        }
                        requested_ip_str = ss.str();
                        i+=5;
                    }
                    //skipping the pad option (0)
                    else if (packet_data[i] == 0) {
                        i += 1;
                    }
                    else{
                        i += int(packet_data[i+1]) + 1;
                    }
                }
                if (is_request && recieved_ip) {
                    requested_ips.push_back(requested_ip_str);
                }
            }
        }
    }
}

//function counting how many ip adresses can be in this subnet
unsigned long int count_ips(std::string ip_prefix) {
    const long unsigned int delimiter_position = ip_prefix.find("/");
    std::string mask = ip_prefix.substr(delimiter_position+1);
    if(stoi(mask) >= 32) return 0;
    unsigned long int ip_count = std::pow(2,(32-stoi(mask)));
    return ip_count;
}

int main(int argc, char **argv) {
    initscr();
    openlog("dhcp-stats",0,LOG_USER);
    
    //user input parsing
    if (parse_args(argc, argv)) {
        return 1;
    }
    
    std::vector<std::string>::iterator iter = ip_prefix.begin();
    for(; iter < ip_prefix.end(); iter++) {
        //saves count of max-hosts ip addresses in subnet
        max_hosts[*iter] = count_ips(*iter);
        is_fifty[*iter] = false;
    }

    //tcpdump capture using libpcap
    //inspired by: https://elf11.github.io/2017/01/22/libpcap-in-C.html
    char err_buffer[PCAP_ERRBUF_SIZE];

    if (!interface_name.empty()) {
        //opening of interface for capturing
        pcap_t *interface = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 100, err_buffer);
        if (interface == NULL) {
            closelog();
            endwin(); 
            std::cerr<<"Error! pcap_open_live() failed: "<<pcap_geterr(interface)<<std::endl;           
            return 1;
        }
        writeout_stats();

        //setting up a handler callback for captured pcap file packets
        if (pcap_loop(interface, 0, ph_routine, NULL) < 0) {
            closelog();
            endwin(); 
            std::cerr<<"Error! pcap_loop() failed: "<<pcap_geterr(interface)<<std::endl;           
            return 1;
        }
    }
    else if (!file_name.empty()) {
        //opening of pcap file for capturing
        pcap_t *opened_file = pcap_open_offline(file_name.c_str(), err_buffer);
        if (opened_file == NULL) {
            closelog();
            endwin();
            std::cerr<<"Error! pcap_open_offline() failed: "<<err_buffer<<std::endl;            
            return 1;
        }
        writeout_stats();

        //setting up a handler callback for captured pcap file packets
        if (pcap_loop(opened_file, 0, ph_routine, NULL) < 0) {
            closelog();
            endwin();
            std::cerr<<"Error! pcap_loop() failed: "<<pcap_geterr(opened_file)<<std::endl;
            return 1;
        }
    }
    else {
        closelog();
        endwin();
        std::cerr<<"Error! Missing parameters (-r or -i).\n";
        return 1;
    }
    getch();
    closelog();
    endwin();
    return 0;
}