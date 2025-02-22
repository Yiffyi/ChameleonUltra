#include "iso14a_ext.h"
#include <string.h>

inline uint8_t pcb_block_num(uint8_t pcb) {
    return pcb & 0x01;
}

inline bool pcb_has_cid(uint8_t pcb) {
    return (pcb & 0x08) == 0x08;
}

nfc_14a_pcb_info_t nfc_14a_decode_pcb(uint8_t pcb) {
    nfc_14a_pcb_info_t info = {
        .block_num = pcb_block_num(pcb),
        .has_cid = pcb_has_cid(pcb),
        .has_nad = false,
        .block_type = pcb >> 6,
        .i_chaining = false,
        .r_ack = false,
        .r_nak = false,
        .s_deselect = false,
        .s_wtx = false
    };


    switch (info.block_type)
    {
    case NFC_14A_BLOCK_TYPE_I:
        info.i_chaining = (pcb & 0x10) == 0x10;
        break;
    case NFC_14A_BLOCK_TYPE_R:
        info.r_ack = (pcb & 0x10) == 0x00;
        info.r_nak = (pcb & 0x20) == 0x20;
        break;
    case NFC_14A_BLOCK_TYPE_S:
        info.s_deselect = (pcb & 0x30) == 0x00;
        info.s_wtx = (pcb & 0x30) == 0x30;
        break;
    }
    
    return info;
}

uint8_t nfc_14a_encode_pcb(nfc_14a_pcb_info_t* p_pcb_info) {
    uint8_t pcb = p_pcb_info->block_type << 6;
    pcb |= (p_pcb_info->has_cid & 0x01) << 3;
    pcb |= (p_pcb_info->has_nad & 0x01) << 2;
    pcb |= p_pcb_info->block_num & 0x01;

    switch (p_pcb_info->block_type)
    {
    case NFC_14A_BLOCK_TYPE_I:
        if (p_pcb_info->i_chaining) {
            pcb |= 0x10;
        }
        break;
    case NFC_14A_BLOCK_TYPE_R:
        if (p_pcb_info->r_ack) {
            pcb &= 0xef;
        }
        if (p_pcb_info->r_nak) {
            pcb |= 0x20;
        }
        break;
    case NFC_14A_BLOCK_TYPE_S:
        if (p_pcb_info->s_deselect) {
            pcb &= 0xcf;
        }
        if (p_pcb_info->s_wtx) {
            pcb |= 0x30;
        }
        break;
    }
}

uint16_t nfc_14a_get_frame_size(nfc_14a_frame_t *p_frame, bool has_crc) {
    uint16_t cb_used = 1;
    if (p_frame->pcb_info->has_cid) {
        cb_used++;
    }

    if (p_frame->pcb_info->has_nad) {
        cb_used++;
    }

    cb_used += p_frame->inf_size;
    if (has_crc) {
        cb_used += 2;
    }

    return cb_used;
}

bool nfc_14a_decode_frame(uint8_t *p_buf, uint16_t cb_buf, nfc_14a_frame_t *p_frame) {

}

bool nfc_14a_encode_frame(nfc_14a_frame_t *p_frame, uint8_t* p_buf, uint16_t* cb_buf) {
    uint16_t cb_used = 1;
    p_buf[0] = nfc_14a_encode_pcb(p_frame->pcb_info);

    if (p_frame->pcb_info->has_cid) {
        p_buf[cb_used++] = p_frame->cid;
    }

    if (p_frame->pcb_info->has_nad) {
        p_buf[cb_used++] = p_frame->nad;
    }

    if (cb_used + p_frame->inf_size > cb_buf) {
        *cb_buf = cb_used + p_frame->inf_size;
        return false;
    } else {
        memcpy(p_buf+cb_used, p_frame->p_inf, p_frame->inf_size);
        cb_used += p_frame->inf_size;
        *cb_buf = cb_used;
        return true;
    }

}