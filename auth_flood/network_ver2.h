#ifndef NETWORK_VER2_H
#define NETWORK_VER2_H

#include <time.h>

#define MAX_SSID_LEN 32
#define MAX_AP 100
#define MAX_CLIENTS 200

// 구조체 정의 공유
typedef struct {
    unsigned char bssid[6];
    char ssid[MAX_SSID_LEN];
    int channel;
    int signal_power;
    int beacon_count;
    int data_count;
    time_t last_seen;
    time_t first_seen;
} APInfo;

typedef struct {
    unsigned char mac[6];
    unsigned char bssid[6];
    char ap_ssid[MAX_SSID_LEN];
    int packet_count;
    time_t first_seen;
    time_t last_seen;
} ClientInfo;

// 다른 파일에서 호출할 스캔 시작 함수 선언
void start_wifi_scan(char *device);

#endif