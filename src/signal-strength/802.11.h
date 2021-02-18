#include <stdint.h>

#pragma pack(push,1)
struct Radiotap_1 {
    uint8_t header_revison;
    uint8_t header_pad;
    uint16_t header_length;
    uint8_t header_presentflag[4];
}; // radiotap_1 8byte
   // header_presentflag 유동적임.

struct Radiotap_2 {
    uint8_t flag;
    uint8_t data_rate;
    uint16_t channel_frequence;
    uint16_t channel_flag;
    uint8_t antenna_signal;
}; // radiotap_2 7byte

struct IEEE_802_11 {
    uint8_t type[2];
    uint16_t duration;
    uint8_t addr1[6] = {0,};
    uint8_t addr2[6] = {0,};
}; // IEEE_802_11 22byte

#pragma pack(pop)
