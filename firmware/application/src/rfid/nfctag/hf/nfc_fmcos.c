#include <stdlib.h>

#include "nfc_fmcos.h"
#include "nfc_14a.h"
#include "hex_utils.h"
#include "fds_util.h"
#include "tag_persistence.h"

#define NRF_LOG_MODULE_NAME tag_fmcos
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
NRF_LOG_MODULE_REGISTER();

#define ISO14443A_IBLOCK 0x00
#define ISO14443A_RBLOCK 0x80
#define ISO14443A_R_ACK 0xA0
#define ISO14443A_R_NAK 0xB0

// Define and use shadow anti -collision resources
static nfc_tag_14a_coll_res_reference_t m_shadow_coll_res;
//Save the specific type of FMCOS currently being simulated
static tag_specific_type_t m_tag_type;

// Data structure pointer to the label information
static nfc_tag_fmcos_information_t *m_tag_info = NULL;
static uint16_t m_tag_df = 0x3F00;
static uint16_t m_tag_ef = 0x0000;
static nfc_tag_fmcos_file_t *m_tag_file = NULL;

nfc_tag_14a_coll_res_reference_t *get_fmcos_coll_res() {
    m_shadow_coll_res.sak = m_tag_info->res_coll.sak;
    m_shadow_coll_res.atqa = m_tag_info->res_coll.atqa;
    m_shadow_coll_res.uid = m_tag_info->res_coll.uid;
    m_shadow_coll_res.size = &(m_tag_info->res_coll.size);
    m_shadow_coll_res.ats = &(m_tag_info->res_coll.ats);
    // Finally, a shadow data structure pointer with only reference, no physical shadow,
    return &m_shadow_coll_res;
}

void fmcos_select_file(uint8_t *p_cmd, uint16_t cb_cmd, uint8_t **pp_inf_end) {
    uint8_t p1 = p_cmd[2], p2 = p_cmd[3];
    uint8_t *p_inf_end = *pp_inf_end;

    uint8_t aid_len = p_cmd[4];
    uint8_t *aid = p_cmd+5;

    uint8_t found = 0;
    if (p1 == 0x00 && p2 == 0x00 && aid_len == 2) {
        uint16_t idx = (((uint16_t)aid[0]) << 8) | aid[1];
        for(nfc_tag_fmcos_file_t *p = (nfc_tag_fmcos_file_t*)m_tag_info->memory; p != NULL; p = p->next) {
            if (p->df_id == idx && p->file_type == NFC_TAG_FMCOS_FILE_TYPE_DIR_FCI) { // is DF
                memcpy(p_inf_end, p->value, p->value_size);
                p_inf_end += p->value_size;

                m_tag_file = NULL;
                m_tag_ef = 0x0000;
                found = 1;
                break;
            }
            if (p->df_id == m_tag_df && p->ef_id == idx) { // is EF
                m_tag_ef = idx;
                m_tag_file = p;
                found = 1;
                break;
            }
        }
    } else if (p1 == 0x40 && p2 == 0x00 && aid_len > 0) {
        nfc_tag_fmcos_file_t *p;
        for(p = (nfc_tag_fmcos_file_t*)m_tag_info->memory; p != NULL; p = p->next) {
            if (p->file_type == NFC_TAG_FMCOS_FILE_TYPE_DIR_NAME && aid_len == p->value_size && memcmp(p->value, aid, p->value_size) == 0) {
                break;
            }
        }

        if (p != NULL) {
            m_tag_file = NULL;
            m_tag_df = p->df_id;
            m_tag_ef = 0x0000;
            found = 1;
            for(p = (nfc_tag_fmcos_file_t*)m_tag_info->memory; p != NULL; p = p->next) {
                if (p->file_type == NFC_TAG_FMCOS_FILE_TYPE_DIR_FCI && p->df_id == m_tag_df) {
                    memcpy(p_inf_end, p->value, p->value_size);
                    p_inf_end += p->value_size;
                    break;
                }
            }
        }

    } else {
        *p_inf_end = 0x6A; p_inf_end++;
        *p_inf_end = 0x86; p_inf_end++;
        *pp_inf_end = p_inf_end;
        return;
    }

    if (found) {
        *p_inf_end = 0x90; p_inf_end++;
        *p_inf_end = 0x00; p_inf_end++;
        *pp_inf_end = p_inf_end;

    } else {
        *p_inf_end = 0x6A; p_inf_end++;
        *p_inf_end = 0x82; p_inf_end++;
        *pp_inf_end = p_inf_end;
    }

    return;
}

void fmcos_read_binary(uint8_t *p_cmd, uint16_t cb_cmd, uint8_t **pp_inf_end) {
    uint8_t p1 = p_cmd[2], p2 = p_cmd[3], le = p_cmd[4];
    uint8_t *p_inf_end = *pp_inf_end;
    uint16_t ef_idx;
    uint16_t offset = 0;
    nfc_tag_fmcos_file_t *file = NULL;
    // support two types of param format

    if ((p1 & 0xE0) == 0x80) {
        ef_idx = p1 & 0x1F;
        offset = p2;
    } else {
        ef_idx = m_tag_ef;
        offset = (p1 << 8) | p2;
    }

    if (ef_idx == m_tag_ef && m_tag_file && m_tag_file->file_type == NFC_TAG_FMCOS_FILE_TYPE_BINARY) {
        file = m_tag_file;
    } else {
        for(nfc_tag_fmcos_file_t *p = (nfc_tag_fmcos_file_t*)m_tag_info->memory; p != NULL; p = p->next) {
            if (p->df_id == m_tag_df && p->ef_id == ef_idx && m_tag_file ->file_type == NFC_TAG_FMCOS_FILE_TYPE_BINARY) { // is EF
                file = p;
                break;
            }
        }
    }

    if (file) {
        if (offset + le > file->value_size - 2) { // too much
            *p_inf_end = 0x6B; p_inf_end++;
            *p_inf_end = 0x00; p_inf_end++;
        } else {
            memcpy(p_inf_end, file->value + offset, le);
            p_inf_end += le;
            *p_inf_end = 0x90; p_inf_end++;
            *p_inf_end = 0x00; p_inf_end++;
        }
    } else {
        *p_inf_end = 0x6A; p_inf_end++;
        *p_inf_end = 0x82; p_inf_end++;
    }
    *pp_inf_end = p_inf_end;
}


void fmcos_get_challenge(uint8_t *p_cmd, uint16_t cb_cmd, uint8_t **pp_inf_end) {
    uint8_t p1 = p_cmd[2], p2 = p_cmd[3], le = p_cmd[4], sw1 = 0x90, sw2 = 0x00;
    uint8_t *p_inf_end = *pp_inf_end;
    // GET CHALLENGE
    if (p1 == 0x00 && p2 == 0x00 && cb_cmd == 5) {
        if (le == 4) {
            num_to_bytes(0xdead, 4, p_inf_end);
            p_inf_end += 4;
            sw1 = 0x90;
            sw2 = 0x00;
        } else if (le == 8) {
            num_to_bytes(0xdead, 4, p_inf_end);
            num_to_bytes(0xbeef, 4, p_inf_end+4);
            p_inf_end += 8;
            sw1 = 0x90;
            sw2 = 0x00;
        } else {
            sw1 = 0x67;
            sw2 = 0x00;
        }
    } else {
        // Incorrect P1 or P2
        sw1 = 0x6A; sw2 = 0x86;
    }
    *p_inf_end = sw1; p_inf_end++;
    *p_inf_end = sw2; p_inf_end++;
    *pp_inf_end = p_inf_end;
    return;
}

void nfc_tag_fmcos_state_handler(uint8_t *p_data, uint16_t szDataBits) {
    static uint8_t tx_buffer[64];
    static uint8_t *p_tx = tx_buffer;

    static uint8_t inf_buffer[NFC_TAG_FMCOS_MAX_RESP_SIZE];
    static uint8_t inf_inflight = 0;
    static uint8_t *p_inf_end = inf_buffer;
    static uint8_t *p_inf = inf_buffer;

    static uint8_t tx_blk_idx = 1;

    if (p_data == NULL) {
        p_inf = p_inf_end = inf_buffer; inf_inflight = 0;
        p_tx = tx_buffer;
        tx_blk_idx = 1;

        m_tag_df = 0x3F00;
        m_tag_ef = 0x0000;
        m_tag_file = NULL;
        return;
    }

    uint16_t cbData = szDataBits >> 3;
    if (cbData < 1) return;

    uint8_t rx_blk_idx = p_data[0] & 0x01;
    uint8_t rx_use_cid = p_data[0] & 0x08;

    switch(p_data[0] & 0xC0) { // type of block
        case ISO14443A_IBLOCK:
        {
            p_inf = p_inf_end = inf_buffer; inf_inflight = 0;
            tx_blk_idx ^= 0x01;
            tx_buffer[0] = (p_data[0] & 0xEE) | tx_blk_idx;
            p_tx = tx_buffer;

            uint8_t *p_cmd;
            uint16_t cb_cmd;
            if (rx_use_cid) {
                p_cmd = p_data + 2;
                cb_cmd = cbData - 2;
            } else {
                p_cmd = p_data + 1;
                cb_cmd = cbData - 1;
            }
            uint8_t ins = p_data[1];
            switch(ins) {
                case 0xA4: fmcos_select_file(p_cmd, cb_cmd, &p_inf_end); break;
                case 0xB0: fmcos_read_binary(p_cmd, cb_cmd, &p_inf_end); break;
                case 0x84: fmcos_get_challenge(p_cmd, cb_cmd, &p_inf_end); break;
                default:
                    inf_buffer[0] = 0x90; inf_buffer[1] = 0x00;
                    p_inf_end = inf_buffer + 2;
            }
        }
        case ISO14443A_RBLOCK:
        {
            if (tx_blk_idx == rx_blk_idx) {
                // missed, resend
            } else {
                switch(p_data[0] & 0xF0) {
                    case ISO14443A_R_ACK:
                    {
                        tx_blk_idx ^= 0x01;
                        tx_buffer[0] =  0x12 | tx_blk_idx; // I chained
                        p_inf += inf_inflight; inf_inflight = 0;
                        p_tx = tx_buffer;
                    }
                    case ISO14443A_R_NAK:
                    {
                        tx_buffer[0] =  0xA2 | tx_blk_idx; // R(ACK)
                        p_inf = p_inf_end = inf_buffer; inf_inflight = 0;
                        p_tx = tx_buffer;
                    }
                }

            }
        }
    }

    if (p_tx == tx_buffer) { // if this is a new buffer
        if (rx_use_cid) {
            tx_buffer[0] |= 0x08; // set CID
            tx_buffer[1] = p_data[1];
            p_tx = tx_buffer + 2;
        } else {
            tx_buffer[0] &= 0xF7; // unset CID
            p_tx = tx_buffer + 1;
        }
    }

    // process INF
    uint16_t fsd = nfc_tag_14a_get_pcd_fsd();
    if ((p_tx - tx_buffer) + 2 + (p_inf_end - p_inf) > fsd) {
        inf_inflight = fsd - (p_tx - tx_buffer);
        memcpy(p_inf, p_tx, inf_inflight);
        nfc_tag_14a_tx_bytes(tx_buffer, inf_inflight + (p_tx - tx_buffer), true);
    } else if (p_inf_end > p_inf) {
        inf_inflight = p_inf_end - p_inf;
        memcpy(p_inf, p_tx, p_inf_end - p_inf);
        nfc_tag_14a_tx_bytes(tx_buffer, inf_inflight + (p_tx - tx_buffer), true);

        p_inf = p_inf_end = inf_buffer;
        inf_inflight = 0;
    } else if (p_tx > tx_buffer) {
        nfc_tag_14a_tx_bytes(tx_buffer, p_tx - tx_buffer, true);
    }


    // if (m_tag_info->config.respond_to_mifare_auth && cbData == 4 && (p_data[0] == MIFARE_AUTH_KEYA || p_data[0] == MIFARE_AUTH_KEYB)) {

    // }
}

void nfc_tag_fmcos_reset_handler() {
    nfc_tag_fmcos_state_handler(NULL, 0);
}

int nfc_tag_fmcos_data_savecb(tag_specific_type_t type, tag_data_buffer_t *buffer) {
    if (m_tag_type == TAG_TYPE_FMCOS_ZJZY) {
        // if (m_tag_info->config.mode_block_write == NFC_TAG_MF1_WRITE_SHADOW) {
        //     NRF_LOG_INFO("The mf1 is shadow write mode.");
        //     return 0;
        // }
        // if (m_tag_info->config.mode_block_write == NFC_TAG_MF1_WRITE_SHADOW_REQ) {
        //     NRF_LOG_INFO("The mf1 will be set to shadow write mode.");
        //     m_tag_info->config.mode_block_write = NFC_TAG_MF1_WRITE_SHADOW;
        // }
        // Save the corresponding size data according to the current label type
        return sizeof(nfc_tag_fmcos_information_t);
    } else {
        return 0;
    }
}

int nfc_tag_fmcos_data_loadcb(tag_specific_type_t type, tag_data_buffer_t *buffer) {
    // Make sure that external capacity is enough to convert to an information structure
    int info_size = sizeof(nfc_tag_fmcos_information_t);
    if (buffer->length >= info_size) {
        //Convert the data buffer to MF1 structure type
        m_tag_info = (nfc_tag_fmcos_information_t *)buffer->buffer;
        // The specific type of MF1 that is simulated by the cache
        m_tag_type = type;
        // Register 14A communication management interface
        nfc_tag_14a_handler_t handler_for_14a = {
            .get_coll_res = get_fmcos_coll_res,
            .cb_state = nfc_tag_fmcos_state_handler,
            .cb_reset = nfc_tag_fmcos_reset_handler,
        };
        nfc_tag_14a_set_handler(&handler_for_14a);
        NRF_LOG_INFO("HF FMCOS data load finish.");
    } else {
        NRF_LOG_ERROR("nfc_tag_fmcos_information_t too big.");
    }
    return info_size;
}

// Factory data for initialization of FMCOS
bool nfc_tag_fmcos_data_factory(uint8_t slot, tag_specific_type_t tag_type) {
    nfc_tag_fmcos_file_t mf = {
        .df_id = 0x3f00,
        .ef_id = 0xffff,
        .file_type = NFC_TAG_FMCOS_FILE_TYPE_DIR_NAME,
        .next = NULL,
        .value_size = 0
    };

    nfc_tag_fmcos_information_t fmcos_tmp_info;
    nfc_tag_fmcos_information_t *p_fmcos_info = &fmcos_tmp_info;

    memcpy(p_fmcos_info->memory, &mf, sizeof(mf));

    p_fmcos_info->config.mode_write = NFC_TAG_FMCOS_WRITE_IGNORE;
    p_fmcos_info->config.respond_to_mifare_auth = 0;

    p_fmcos_info->res_coll.atqa[0] = 0x04;
    p_fmcos_info->res_coll.atqa[1] = 0x00;
    p_fmcos_info->res_coll.sak[0] = 0x08;
    p_fmcos_info->res_coll.uid[0] = 0xDE;
    p_fmcos_info->res_coll.uid[1] = 0xAD;
    p_fmcos_info->res_coll.uid[2] = 0xBE;
    p_fmcos_info->res_coll.uid[3] = 0xEF;
    p_fmcos_info->res_coll.size = NFC_TAG_14A_UID_SINGLE_SIZE;
    p_fmcos_info->res_coll.ats.length = 0;

    // save data to flash
    tag_sense_type_t sense_type = get_sense_type_from_tag_type(tag_type);
    fds_slot_record_map_t map_info;
    get_fds_map_by_slot_sense_type_for_dump(slot, sense_type, &map_info);
    int info_size = sizeof(nfc_tag_fmcos_information_t);
    NRF_LOG_INFO("FMCOS info size: %d", info_size);
    bool ret = fds_write_sync(map_info.id, map_info.key, info_size, p_fmcos_info);
    if (ret) {
        NRF_LOG_INFO("Factory slot data success.");
    } else {
        NRF_LOG_ERROR("Factory slot data error.");
    }
    return ret;
}
