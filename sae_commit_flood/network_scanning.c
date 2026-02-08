#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>


#define MAX_AP 100
#define MAX_CLIENTS 200
#define MAX_SSID_LEN 32

typedef struct{
    unsigned char bssid[6];
    char ssid[MAX_SSID_LEN];
    int channel;
    int signal_power;
    int beacon_count;
    int data_count;
    time_t last_seen;
    time_t first_seen;
} APInfo;

typedef struct{
    unsigned char mac[6];
    unsigned char bssid[6];
    int signal_power;  // 오타 수정: signal_pwoer -> signal_power
    int packet_count;  // 오타 수정: packer_count -> packet_count
    time_t first_seen;
    time_t last_seen;
} ClientInfo;

APInfo ap_list[MAX_AP];
int ap_count = 0;
ClientInfo client_info_list[MAX_CLIENTS];
int client_count = 0;
int running = 1;

void signal_handler(int sig){
    running = 0;
    printf("\nStopping network scanning...\n");
}

void print_ap_table(){
    system("clear");
    printf("=== WiFi Scanner ===\n");
    printf(" BSSID              PWR  Beacons  #Data  CH  ESSID\n");
    printf("--------------------------------------------------\n");

    if (ap_count == 0) {
        printf(" No APs found yet...\n");
    } else {
        for(int i = 0; i < ap_count && i < 20; i++){
            APInfo *ap = &ap_list[i];
            printf(" %02X:%02X:%02X:%02X:%02X:%02X  %3d  %7d  %5d  %2d  %s\n",
                   ap->bssid[0], ap->bssid[1], ap->bssid[2],
                   ap->bssid[3], ap->bssid[4], ap->bssid[5],
                   ap->signal_power,
                   ap->beacon_count,
                   ap->data_count,
                   ap->channel,
                   ap->ssid);
        }
    }

    printf("\n APs: %d  Clients: %d\n", ap_count, client_count);
    printf(" Press Ctrl+C to exit\n");
}

// Radiotap 헤더 길이 추출 함수 추가
int get_radiotap_length(const unsigned char *packet) {
    // Radiotap 헤더 길이는 2번째, 3번째 바이트 (little-endian)
    if (packet[0] != 0x00) { // Radiotap 버전 0
        return 8; // 기본 길이
    }
    return packet[2] | (packet[3] << 8);
}

int find_ap(unsigned char *bssid){
    for (int i = 0; i < ap_count; i++){
        if(memcmp(ap_list[i].bssid, bssid, 6) == 0){
            return i;
        }
    }
    return -1;
}

int find_client(unsigned char *mac){
    for (int i = 0; i < client_count; i++){
        if(memcmp(client_info_list[i].mac, mac, 6) == 0){
            return i;
        }
    }
    return -1;
}

void process_packet(__u_char *args, const struct pcap_pkthdr *header, const __u_char *packet){
    // 패킷 길이 확인
    if(header->len < 36) return; // 최소 길이 증가
    
    // Radiotap 헤더 길이 계산
    int radiotap_len = get_radiotap_length(packet);
    if (radiotap_len >= header->len) {
        return;
    }
    
    // 802.11 프레임 시작점
    const unsigned char *wlan_frame = packet + radiotap_len;
    int wlan_len = header->len - radiotap_len;
    
    if (wlan_len < 24) return; // 802.11 헤더 최소 길이
    
    // 프레임 컨트롤 필드
    int frame_type = (wlan_frame[0] & 0x0C) >> 2;
    int frame_subtype = (wlan_frame[0] & 0xF0) >> 4;
    
    // Beacon 프레임 처리
    if(frame_type == 0 && frame_subtype == 8){
        if (wlan_len < 36) return;
        
        // BSSID (Address 3)
        unsigned char bssid[6];
        memcpy(bssid, wlan_frame + 16, 6);
        
        // SSID 추출
        int offset = 36;
        if (offset >= wlan_len) return;
        
        char ssid[MAX_SSID_LEN] = {0};
        int ssid_len = wlan_frame[offset];
        
        if(ssid_len > 0 && ssid_len < MAX_SSID_LEN && (offset + 1 + ssid_len) <= wlan_len){
            memcpy(ssid, wlan_frame + offset + 1, ssid_len);
            ssid[ssid_len] = '\0';
        } else {
            strcpy(ssid, "<hidden>");
        }
        
        // 채널 추출 (DS Parameter)
        int channel = 0;
        int i = offset + 1 + ssid_len;
        while(i < wlan_len - 1){
            int element_id = wlan_frame[i];
            int element_len = wlan_frame[i + 1];
            
            if (element_id == 3 && element_len == 1) { // DS Parameter
                channel = wlan_frame[i + 2];
                break;
            }
            
            i += 2 + element_len;
            if (element_len == 0) break;
        }
        
        // 신호 강도 추정 (간단하게 RSSI)
        int signal = -100;
        // Radiotap 헤더에서 신호 강도 찾기 (위치에 따라 다름)
        if (radiotap_len >= 16) {
            signal = -(256 - packet[16]); // 간단한 추정
        }
        
        int ap_index = find_ap(bssid);
        if (ap_index == -1 && ap_count < MAX_AP){
            APInfo *ap = &ap_list[ap_count];
            memcpy(ap->bssid, bssid, 6);
            strncpy(ap->ssid, ssid, MAX_SSID_LEN - 1);
            ap->ssid[MAX_SSID_LEN - 1] = '\0';
            ap->channel = channel;
            ap->signal_power = signal;
            ap->beacon_count = 1;
            ap->data_count = 0;
            ap->first_seen = time(NULL);
            ap->last_seen = time(NULL);
            ap_count++;
            
            // 첫 AP 발견 시 출력
            printf("Found new AP: %s\n", ssid);
        } else if (ap_index != -1){
            ap_list[ap_index].beacon_count++;
            ap_list[ap_index].last_seen = time(NULL);
            
            // 더 강한 신호로 업데이트
            if (signal > ap_list[ap_index].signal_power) {
                ap_list[ap_index].signal_power = signal;
            }
            
            if(channel != 0){
                ap_list[ap_index].channel = channel;
            }
        }
    }
    
    // 데이터 프레임 처리
    else if(frame_type == 2){
        if (wlan_len < 24) return;
        
        unsigned char addr1[6], addr2[6]; // addr1: 수신자, addr2: 송신자
        memcpy(addr1, wlan_frame + 4, 6);
        memcpy(addr2, wlan_frame + 10, 6);
        
        unsigned char ap_mac[6], client_mac[6];
        
        // AP가 송신자인지 수신자인지 확인
        int addr1_is_ap = find_ap(addr1) != -1;
        int addr2_is_ap = find_ap(addr2) != -1;
        
        if (addr2_is_ap) { // 송신자가 AP
            memcpy(ap_mac, addr2, 6);
            memcpy(client_mac, addr1, 6);
        } else if (addr1_is_ap) { // 수신자가 AP
            memcpy(ap_mac, addr1, 6);
            memcpy(client_mac, addr2, 6);
        } else {
            return; // AP와 관련 없는 패킷
        }
        
        // AP의 데이터 카운트 증가
        int ap_index = find_ap(ap_mac);
        if(ap_index != -1){
            ap_list[ap_index].data_count++;
        }
        
        // 클라이언트 정보 업데이트
        int client_index = find_client(client_mac);
        if(client_index == -1 && client_count < MAX_CLIENTS){
            ClientInfo *client = &client_info_list[client_count];
            memcpy(client->mac, client_mac, 6);
            memcpy(client->bssid, ap_mac, 6);
            client->signal_power = -70; // 기본값
            client->packet_count = 1;
            client->first_seen = time(NULL);
            client->last_seen = time(NULL);
            client_count++;
        } else if (client_index != -1){
            client_info_list[client_index].packet_count++;
            client_info_list[client_index].last_seen = time(NULL);
        }
    }
}

int main(int argc, char *argv[]){
    char *dev = "wlan0mon";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    
    // 더 간단한 필터
    char filter_exp[] = "wlan type mgt subtype beacon or wlan type data";
    
    if (argc > 1){
        dev = argv[1];
    }
    
    printf("=== C WiFi Scanner ===\n");
    printf("Interface: %s\n", dev);
    printf("Starting scan... (Press Ctrl+C to stop)\n\n");
    
    // 인터페이스 확인을 위한 테스트
    printf("Testing interface...\n");
    char test_cmd[100];
    sprintf(test_cmd, "iwconfig %s 2>&1 | grep -i mode", dev);
    system(test_cmd);
    
    signal(SIGINT, signal_handler);
    
    // pcap 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL){
        fprintf(stderr, "ERROR: Couldn't open device %s: %s\n", dev, errbuf);
        fprintf(stderr, "Check if:\n");
        fprintf(stderr, "1. Interface exists: ip link show | grep %s\n", dev);
        fprintf(stderr, "2. You have permission (run with sudo)\n");
        fprintf(stderr, "3. Interface is in monitor mode\n");
        return 2;
    }
    
    printf("Device opened successfully!\n");
    
    // 필터 컴파일
    if(pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1){
        fprintf(stderr, "ERROR: Couldn't parse filter %s: %s\n", 
                filter_exp, pcap_geterr(handle));
        
        // 더 간단한 필터 시도
        printf("Trying simpler filter...\n");
        strcpy(filter_exp, "ether proto 0x888e"); // EAPOL 패킷
        if(pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1){
            pcap_close(handle);
            return 2;
        }
    }
    
    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "ERROR: Couldn't install filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 2;
    }
    
    printf("Filter installed. Waiting for packets...\n");
    sleep(2); // 잠시 대기
    
    time_t last_display = 0;
    int packet_count = 0;
    
    while(running){
        struct pcap_pkthdr header;
        const __u_char *packet = pcap_next(handle, &header);
        
        if(packet != NULL){
            packet_count++;
            process_packet(NULL, &header, packet);
            
            // 첫 몇 개 패킷 디버깅
            if (packet_count <= 5) {
                printf("Received packet #%d, len=%d\n", packet_count, header.len);
            }
        }
        
        time_t now = time(NULL);
        if(now - last_display >= 2){ // 2초마다 화면 갱신
            print_ap_table();
            printf("Total packets: %d\n", packet_count);
            last_display = now;
        }
        
        usleep(10000); // 10ms 대기 (CPU 사용량 줄이기)
    }
    
    pcap_close(handle);
    printf("\nScan complete.\n");
    printf("Total packets processed: %d\n", packet_count);
    printf("Total APs found: %d\n", ap_count);
    printf("Total clients found: %d\n", client_count);
    printf("Exiting.\n");
    
    return 0;
}