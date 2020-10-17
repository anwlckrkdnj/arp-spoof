#pragma once

#include <stdbool.h>
#include "mac.h"
#include "ip.h"

bool getUserMac(char* interface, Mac* attacker_mac, Ip* attacker_ip, Mac* user_mac, Ip* user_ip);
bool beginSpoof(char* interface, Mac* attacker_mac, Ip* attacker_ip, Mac* sender_mac, Ip* sender_ip, Ip* target_ip, int flow);
bool keepSpoof(char* interface, Mac* attacker_mac, Ip* attacker_ip, Mac* sender_mac, Ip* sender_ip, Mac* target_mac, Ip* target_ip, int flow);
void endSpoof(char* interface, Mac* attacker_mac, Mac* sender_mac, Ip* sender_ip, Mac* target_mac, Ip* target_ip, int flow);
