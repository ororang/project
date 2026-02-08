#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include "network_ver2.h"

#define MAX_AP 100
#define MAX_CLIENTS 200
#define MAX_SSID_LEN 32


APInfo ap_list[MAX_AP];
int ap_count = 0;
ClientInfo client_list[MAX_CLIENTS];
int client_count = 0;
int running = 1;

void signal_handler(int sig) {
    running = 0;
    printf("\n스캔 중지...\n");
}

// AP 정보 업데이트
int update_ap_info(unsigned char *bssid, char *ssid, int channel, int signal) {
    for (int i = 0; i < ap_count; i++) {
        if (memcmp(ap_list[i].bssid, bssid, 6) == 0) {
            // AP 정보 업데이트
            ap_list[i].beacon_count++;
            ap_list[i].last_seen = time(NULL);
            
            // SSID가 있고 기존이 hidden이면 업데이트
            if (strlen(ssid) > 0 && strcmp(ap_list[i].ssid, "<hidden>") == 0) {
                strncpy(ap_list[i].ssid, ssid, MAX_SSID_LEN - 1);
                ap_list[i].ssid[MAX_SSID_LEN - 1] = '\0';
            }
            
            // 신호 강도 업데이트 (더 강한 신호로)
            if (signal > ap_list[i].signal_power) {
                ap_list[i].signal_power = signal;
            }
            
            // 채널 업데이트
            if (channel > 0) {
                ap_list[i].channel = channel;
            }
            
            return i; // AP 인덱스 반환
        }
    }
    
    // 새 AP 추가
    if (ap_count < MAX_AP) {
        APInfo *ap = &ap_list[ap_count];
        memcpy(ap->bssid, bssid, 6);
        
        if (strlen(ssid) > 0) {
            strncpy(ap->ssid, ssid, MAX_SSID_LEN - 1);
            ap->ssid[MAX_SSID_LEN - 1] = '\0';
        } else {
            strcpy(ap->ssid, "<hidden>");
        }
        
        ap->channel = channel;
        ap->signal_power = signal;
        ap->beacon_count = 1;
        ap->data_count = 0;
        ap->first_seen = time(NULL);
        ap->last_seen = time(NULL);
        
        printf("[NEW AP] %02X:%02X:%02X:%02X:%02X:%02X - %s\n",
               bssid[0], bssid[1], bssid[2],
               bssid[3], bssid[4], bssid[5],
               ap->ssid);
        
        return ap_count++;
    }
    
    return -1;
}

// 클라이언트 정보 업데이트
void update_client_info(unsigned char *client_mac, unsigned char *ap_bssid, char *ap_ssid) {
    for (int i = 0; i < client_count; i++) {
        if (memcmp(client_list[i].mac, client_mac, 6) == 0) {
            // 기존 클라이언트 업데이트
            client_list[i].packet_count++;
            client_list[i].last_seen = time(NULL);
            
            // AP 정보 업데이트 (연결 변경 가능)
            if (memcmp(client_list[i].bssid, ap_bssid, 6) != 0) {
                memcpy(client_list[i].bssid, ap_bssid, 6);
                strncpy(client_list[i].ap_ssid, ap_ssid, MAX_SSID_LEN - 1);
                client_list[i].ap_ssid[MAX_SSID_LEN - 1] = '\0';
            }
            
            return;
        }
    }
    
    // 새 클라이언트 추가
    if (client_count < MAX_CLIENTS) {
        ClientInfo *client = &client_list[client_count];
        memcpy(client->mac, client_mac, 6);
        memcpy(client->bssid, ap_bssid, 6);
        strncpy(client->ap_ssid, ap_ssid, MAX_SSID_LEN - 1);
        client->ap_ssid[MAX_SSID_LEN - 1] = '\0';
        client->packet_count = 1;
        client->first_seen = time(NULL);
        client->last_seen = time(NULL);
        
        printf("[NEW Client] %02X:%02X:%02X:%02X:%02X:%02X -> AP: %s\n",
               client_mac[0], client_mac[1], client_mac[2],
               client_mac[3], client_mac[4], client_mac[5],
               ap_ssid);
        
        client_count++;
    }
}

// AP의 데이터 카운트 증가
void increment_ap_data_count(unsigned char *ap_bssid) {
    for (int i = 0; i < ap_count; i++) {
        if (memcmp(ap_list[i].bssid, ap_bssid, 6) == 0) {
            ap_list[i].data_count++;
            break;
        }
    }
}

// 화면 출력
void print_display() {
    system("clear");
    printf("=== Wi-Fi Network Scanner ===\n");
    printf("APs: %d, Clients: %d\n\n", ap_count, client_count);
    
    // AP 목록 출력
    printf("[Access Points]\n");
    printf("BSSID              CH  PWR  Beacons  Data  ESSID\n");
    printf("------------------------------------------------\n");
    
    for (int i = 0; i < ap_count && i < 15; i++) {
        APInfo *ap = &ap_list[i];
        printf("%02X:%02X:%02X:%02X:%02X:%02X  %2d  %3d  %7d  %4d  %s\n",
               ap->bssid[0], ap->bssid[1], ap->bssid[2],
               ap->bssid[3], ap->bssid[4], ap->bssid[5],
               ap->channel,
               ap->signal_power,
               ap->beacon_count,
               ap->data_count,
               ap->ssid);
    }
    
    // 연결된 클라이언트 출력
    printf("\n[Connected Clients]\n");
    printf("Client MAC          ->  AP BSSID           AP ESSID\n");
    printf("---------------------------------------------------\n");
    
    int client_display_count = 0;
    for (int i = 0; i < client_count && client_display_count < 10; i++) {
        ClientInfo *client = &client_list[i];
        
        // 연결된 AP 찾기
        char ap_ssid[MAX_SSID_LEN] = "<unknown>";
        for (int j = 0; j < ap_count; j++) {
            if (memcmp(ap_list[j].bssid, client->bssid, 6) == 0) {
                strcpy(ap_ssid, ap_list[j].ssid);
                break;
            }
        }
        
        printf("%02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X  %s\n",
               client->mac[0], client->mac[1], client->mac[2],
               client->mac[3], client->mac[4], client->mac[5],
               client->bssid[0], client->bssid[1], client->bssid[2],
               client->bssid[3], client->bssid[4], client->bssid[5],
               ap_ssid);
        
        client_display_count++;
    }
    
    printf("\n[Controls] Ctrl+C to exit\n");
}

// 802.11 프레임 파싱
// 802.11 프레임 파싱 (수정본: SSID 태그 검색 및 한글 지원)
void parse_80211_frame(const __u_char *packet, int packet_len) {
    if (packet_len < 4) return;
    
    // 변수 선언
    int signal_strength = -100;

    // Radiotap 헤더 길이 동적 계산
    int radiotap_len = packet[2] + (packet[3] << 8);
    if (radiotap_len <= 0 || radiotap_len >= packet_len) return;

    // 신호 강도 가져오기 (보통 안테나 신호는 radiotap 헤더 끝부분 근처에 있음)
    // 정확한 오프셋은 드라이버마다 다르지만, 보통 PWR_DBM은 끝에서 찾을 수 있음
    if (radiotap_len > 22 && packet_len > 22) {
         signal_strength = (signed char)packet[22];
         if (signal_strength >= 0) signal_strength = -100;
    }

    const __u_char *wlan = packet + radiotap_len;
    int wlan_len = packet_len - radiotap_len;
    
    if (wlan_len < 24) return;
    
    int frame_type = (wlan[0] & 0x0C) >> 2;
    int frame_subtype = (wlan[0] & 0xF0) >> 4;
    
    // ==========================================================
    // 1. Beacon Frame (AP 정보)
    // ==========================================================
    if (frame_type == 0 && frame_subtype == 8) {
        if (wlan_len < 36) return;
        
        unsigned char bssid[6];
        memcpy(bssid, wlan + 16, 6);
        
        char ssid[MAX_SSID_LEN] = {0};
        int channel = 0;

        // Beacon 프레임 구조: [Header 24] + [Fixed Params 12] + [Tagged Params...]
        // Tagged Params 시작 위치 = 24 + 12 = 36
        int pos = 36;

        // 태그(IE) 파싱 루프: 정확한 SSID와 채널을 찾기 위해 전체를 훑습니다.
        while (pos < wlan_len - 2) {
            int id = wlan[pos];         // 태그 ID
            int len = wlan[pos + 1];    // 태그 길이
            
            if (pos + 2 + len > wlan_len) break; // 안전장치

            // Tag 0: SSID
            if (id == 0) {
                if (len > 0 && len < MAX_SSID_LEN) {
                    memcpy(ssid, wlan + pos + 2, len);
                    ssid[len] = '\0';
                    
                    // [수정] 한글(UTF-8) 지원을 위해 isprint 체크 로직 제거
                    // 제어 문자(0~31)만 걸러내고 나머지는 그대로 둠
                    for(int k=0; k<len; k++) {
                        if ((unsigned char)ssid[k] < 32) ssid[k] = '.';
                    }
                }
            }
            // Tag 3: DS Parameter (현재 채널 정보)
            else if (id == 3 && len == 1) {
                channel = (int)wlan[pos + 2];
            }

            pos += 2 + len; // 다음 태그로 이동
        }

        // SSID를 못 찾았거나 길이가 0이면 hidden 처리
        if (strlen(ssid) == 0) strcpy(ssid, "<hidden>");
        
        update_ap_info(bssid, ssid, channel, signal_strength);
    }
    
    // ==========================================================
    // 2. Data Frame (클라이언트 트래픽)
    // ==========================================================
    else if (frame_type == 2) {
        if (wlan_len < 24) return;
        
        unsigned char addr1[6], addr2[6], addr3[6];
        memcpy(addr1, wlan + 4, 6);
        memcpy(addr2, wlan + 10, 6);
        memcpy(addr3, wlan + 16, 6);
        
        int to_ds = (wlan[1] & 0x01);
        int from_ds = (wlan[1] & 0x02) >> 1;
        
        unsigned char client_mac[6], ap_bssid[6];
        int valid = 0;

        if (to_ds == 1 && from_ds == 0) {       // Client -> AP
            memcpy(client_mac, addr2, 6);
            memcpy(ap_bssid, addr3, 6);
            valid = 1;
        } else if (to_ds == 0 && from_ds == 1) { // AP -> Client
            memcpy(ap_bssid, addr2, 6);
            memcpy(client_mac, addr1, 6);
            valid = 1;
        }

        if (valid) {
            char ap_ssid[MAX_SSID_LEN] = "<unknown>";
            for (int i = 0; i < ap_count; i++) {
                if (memcmp(ap_list[i].bssid, ap_bssid, 6) == 0) {
                    strcpy(ap_ssid, ap_list[i].ssid);
                    break;
                }
            }
            increment_ap_data_count(ap_bssid);
            update_client_info(client_mac, ap_bssid, ap_ssid);
        }
    }
    
    // ==========================================================
    // 3. Probe Response (숨겨진 네트워크 이름 찾기용)
    // ==========================================================
    else if (frame_type == 0 && frame_subtype == 5) { 
        // Probe Response도 Beacon과 구조가 비슷함
        if (wlan_len < 36) return;
        
        unsigned char bssid[6];
        memcpy(bssid, wlan + 16, 6);
        
        char ssid[MAX_SSID_LEN] = {0};
        int channel = 0;
        int pos = 36; // Header(24) + Fixed(12)

        while (pos < wlan_len - 2) {
            int id = wlan[pos];
            int len = wlan[pos + 1];
            if (pos + 2 + len > wlan_len) break;

            if (id == 0 && len > 0 && len < MAX_SSID_LEN) {
                memcpy(ssid, wlan + pos + 2, len);
                ssid[len] = '\0';
                // 한글 깨짐 방지 (제어 문자만 필터링)
                for(int k=0; k<len; k++) {
                    if ((unsigned char)ssid[k] < 32) ssid[k] = '.';
                }
            }
            else if (id == 3 && len == 1) {
                channel = (int)wlan[pos + 2];
            }
            pos += 2 + len;
        }

        if (strlen(ssid) > 0) {
            update_ap_info(bssid, ssid, channel, signal_strength);
        }
    }
}

// 패킷 핸들러
void packet_handler(__u_char *args, const struct pcap_pkthdr *header, const __u_char *packet) {
    parse_80211_frame(packet, header->len);
}

void start_wifi_scan(char *device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "type mgt or type data";
    
    printf("=== Wi-Fi Network Scanner ===\n");
    printf("Interface: %s\n", device);
    printf("Looking for APs and connected clients...\n\n");
    
    signal(SIGINT, signal_handler);
    
    // pcap 열기
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return ;
    }
    
    // 필터 설정
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Filter error\n");
        pcap_close(handle);
        return ;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Filter set error\n");
        pcap_close(handle);
        return ;
    }
    
    printf("Scanner started. Capturing packets...\n\n");
    
    time_t last_display = 0;
    int packet_count = 0;

    printf("10초 동안 스캔을 시작합니다...\n");
    
    time_t start_time = time(NULL); // 시작 시간 기록
    running = 1;
    
    // 메인 루프
    while (running) {
        struct pcap_pkthdr *header;
        const __u_char *packet;
        
        // 패킷 하나 읽기 (pcap_next_ex 사용)
        int res = pcap_next_ex(handle, &header, &packet);
        
        if (res == 1) { // 패킷을 성공적으로 읽었을 때
            packet_handler(NULL, header, packet);
        }

        // [핵심 로직] 현재 시간과 시작 시간을 비교하여 3초가 지났는지 체크
        if (time(NULL) - start_time >= 10) {
            printf("\n10초가 경과되어 스캔을 종료합니다.\n");
            break; 
        }
    }
    
    pcap_close(handle);

    printf("\n=== Scan Results ===\n");
    printf("Total packets: %d\n", packet_count);
    printf("APs found: %d\n", ap_count);
    printf("Clients found: %d\n", client_count);
    
    // 최종 AP 목록
    if (ap_count > 0) {
        printf("\n[Final AP List]\n");
        for (int i = 0; i < ap_count; i++) {
            APInfo *ap = &ap_list[i];
            printf("AP %02X:%02X:%02X:%02X:%02X:%02X - %s (CH:%d)\n",
                   ap->bssid[0], ap->bssid[1], ap->bssid[2],
                   ap->bssid[3], ap->bssid[4], ap->bssid[5],
                   ap->ssid, ap->channel);
        }
    }
    
    // 최종 클라이언트 목록
    if (client_count > 0) {
        printf("\n[Final Client List]\n");
        for (int i = 0; i < client_count; i++) {
            ClientInfo *client = &client_list[i];
            printf("Client %02X:%02X:%02X:%02X:%02X:%02X -> AP: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   client->mac[0], client->mac[1], client->mac[2],
                   client->mac[3], client->mac[4], client->mac[5],
                   client->bssid[0], client->bssid[1], client->bssid[2],
                   client->bssid[3], client->bssid[4], client->bssid[5]);
        }
    }
    
    printf("\nProgram terminated.\n");
    return ;
}