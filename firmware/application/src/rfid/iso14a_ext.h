#ifndef _ISO14A_H
#define _ISO14A_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    NFC_14A_BLOCK_TYPE_I = (uint8_t)0x00u,
    NFC_14A_BLOCK_TYPE_R = (uint8_t)0x02u,
    NFC_14A_BLOCK_TYPE_S = (uint8_t)0x03u,
} nfc_14a_block_type_t;

typedef struct {
    uint8_t block_num;
    bool has_cid;
    bool has_nad;

    nfc_14a_block_type_t block_type;

    // I specific
    bool i_chaining;
    
    // R specific
    bool r_nak;
    bool r_ack;

    // S specific
    bool s_wtx;
    bool s_deselect;
} nfc_14a_pcb_info_t;

typedef struct {
    nfc_14a_pcb_info_t *pcb_info;
    uint8_t cid, nad;

    uint16_t inf_size;
    uint8_t *p_inf;
} nfc_14a_frame_t;

nfc_14a_pcb_info_t nfc_14a_decode_pcb(uint8_t pcb);
uint8_t nfc_14a_encode_pcb(nfc_14a_pcb_info_t* p_pcb_info);

uint16_t nfc_14a_get_frame_size(nfc_14a_frame_t *p_frame, bool has_crc);
bool nfc_14a_decode_frame(uint8_t *p_buf, uint16_t cb_buf, nfc_14a_frame_t *p_frame);
bool nfc_14a_encode_frame(nfc_14a_frame_t *p_frame, uint8_t* p_buf, uint16_t* cb_buf);
#endif