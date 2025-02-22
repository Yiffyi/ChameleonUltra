#include <stdlib.h>

#include "rfid_main.h"
#include "nfc_fmcos.h"
#include "nfc_14a.h"
#include "iso14a_ext.h"
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
    static uint8_t tx_buffer[NFC_TAG_FMCOS_MAX_RESP_SIZE];
    static uint16_t tx_len = 0;
    // static uint8_t *p_tx = tx_buffer;

    static uint8_t inf_buffer[NFC_TAG_FMCOS_MAX_RESP_SIZE];
    // static uint8_t inf_inflight = 0;
    static uint8_t *p_inf_end = inf_buffer;
    // static uint8_t *p_inf = inf_buffer;

    static nfc_14a_pcb_info_t tx_pcb = {
        .has_cid = false,
        .has_nad = false,
        .block_num = 1
    };

    static nfc_14a_frame_t tx_frame = {
        .pcb_info = &tx_pcb,
        .inf_size = 0,
        .p_inf = inf_buffer
    };
    if (p_data == NULL) {
        // p_inf = p_inf_end = inf_buffer; inf_inflight = 0;
        // p_tx = tx_buffer;
        p_inf_end = inf_buffer;
        tx_len = 0;
        
        tx_pcb.block_num = 1;
        tx_pcb.has_cid = false;
        tx_pcb.has_nad = false;

        tx_frame.cid = 0;
        tx_frame.nad = 0;
        tx_frame.inf_size = 0;
        tx_frame.p_inf = inf_buffer;
        tx_frame.pcb_info = &tx_pcb;

        m_tag_df = 0x3F00;
        m_tag_ef = 0x0000;
        m_tag_file = NULL;
        return;
    }

    uint16_t cbData = szDataBits >> 3;
    if (cbData < 3) return; // min: 1 for PCB, 2 for CRC

    if (!nfc_tag_14a_checks_crc(p_data, cbData)) return;
    cbData -= 2; // we don't care CRC

    nfc_14a_pcb_info_t rx_pcb;
    nfc_14a_frame_t rx_frame = {
        .pcb_info = &rx_pcb,
    };
    if (!nfc_14a_decode_frame(p_data, cbData, &rx_frame)) return;


    switch(rx_frame.pcb_info->block_type) {
        case NFC_14A_BLOCK_TYPE_I:
        {
            tx_pcb.block_num ^= 1;
            tx_frame.p_inf = inf_buffer;
            p_inf_end = inf_buffer;

            if (rx_pcb.has_cid) { // this is not good
                tx_pcb.has_cid = true;
                tx_frame.cid = rx_frame.cid;
            } else {
                tx_pcb.has_cid = false;
            }
            uint8_t ins = rx_frame.p_inf[0];
            switch(ins) {
                case 0xA4: fmcos_select_file(rx_frame.p_inf, rx_frame.inf_size, &p_inf_end); break;
                case 0xB0: fmcos_read_binary(rx_frame.p_inf, rx_frame.inf_size, &p_inf_end); break;
                case 0x84: fmcos_get_challenge(rx_frame.p_inf, rx_frame.inf_size, &p_inf_end); break;
                default:
                    tx_frame.p_inf[0] = 0x90; tx_frame.p_inf[1] = 0x00;
                    tx_frame.inf_size = 2;
            }
            break;
        }
        case NFC_14A_BLOCK_TYPE_R:
        {
            if (tx_pcb.block_num != rx_pcb.block_num) {
                
                if (rx_pcb.has_cid) { // this is not good
                    tx_pcb.has_cid = true;
                    tx_frame.cid = rx_frame.cid;
                } else {
                    tx_pcb.has_cid = false;
                }

                if (rx_pcb.r_ack) {
                    tx_pcb.block_num ^= 1;
                    if (tx_pcb.block_type == NFC_14A_BLOCK_TYPE_I && tx_pcb.i_chaining) {
                        tx_frame.p_inf += tx_frame.inf_size;
                        tx_frame.inf_size = p_inf_end - tx_frame.p_inf; // later code will determine if further chaining is needed
                    }
                    // tx_pcb.block_type = NFC_14A_BLOCK_TYPE_I;
                    // tx_pcb.i_chaining = true;
                }

                if (rx_pcb.r_nak) {
                    tx_pcb.block_type = NFC_14A_BLOCK_TYPE_R;
                    tx_pcb.r_ack = true;
                    tx_pcb.r_nak = false;
                    tx_frame.p_inf = inf_buffer;
                    tx_frame.inf_size = 0;
                }
            } else {
                // resend
            }
            break;
        }
        case NFC_14A_BLOCK_TYPE_S:
        {
            break;
        }
    }

    // process INF
    uint16_t fsd = nfc_tag_14a_get_pcd_fsd();
    uint16_t total_resp_size = nfc_14a_get_frame_size(&tx_frame, true);

    if (total_resp_size > fsd) {
        tx_pcb.i_chaining = true;
        tx_frame.inf_size -= total_resp_size - fsd;
    } else {
        tx_pcb.i_chaining = false;
    }

    nfc_14a_encode_frame(&tx_frame, tx_buffer, &tx_len);
    nfc_tag_14a_tx_bytes(tx_buffer, tx_len, true);

    // if (m_tag_info->config.respond_to_mifare_auth && cbData == 4 && (p_data[0] == MIFARE_AUTH_KEYA || p_data[0] == MIFARE_AUTH_KEYB)) {

    // }
}

void nfc_tag_fmcos_reset_handler() {
    nfc_tag_fmcos_state_handler(NULL, 0);
}

int nfc_tag_fmcos_data_savecb(tag_specific_type_t type, tag_data_buffer_t *buffer) {
    if (m_tag_type == TAG_TYPE_FMCOS_ZJZY) {
        if (m_tag_info->config.mode_write == NFC_TAG_FMCOS_WRITE_SHADOW) {
            NRF_LOG_INFO("The FMCOS is shadow write mode.");
            return 0;
        }
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
        .value_size = 16
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

bool fmcos_add_file(nfc_tag_fmcos_information_t *tag_info, uint16_t df_id, uint16_t ef_id, nfc_tag_fmcos_file_type_t file_type, uint8_t *value, uint16_t value_size) {
    static nfc_tag_fmcos_file_t f;
    f = (nfc_tag_fmcos_file_t){
        .df_id = df_id,
        .ef_id = ef_id,
        .file_type = file_type,
        .next = NULL,
        .value_size = value_size
    };

    for(nfc_tag_fmcos_file_t *p = (nfc_tag_fmcos_file_t*)tag_info->memory; p != NULL; p = p->next) {
        if (p->df_id == df_id && p->ef_id == ef_id && p->file_type == file_type && p->value_size >= value_size) { // extending existing file is not supported
            memcpy(p->value, value, value_size);
            p->value_size = value_size;
            return true;
        }

        if (p->next == NULL) { // we have reached the end.
            p->next = (nfc_tag_fmcos_file_t *)(p->value + p->value_size);
            memcpy(p->next, &f, sizeof(nfc_tag_fmcos_file_t));
            memcpy(p->next->value, value, value_size);
            return true;
        }
    }
    return false;
}

bool fmcos_clone_read_binary_file(uint8_t len, nfc_14a_frame_t *tx_frame, nfc_14a_frame_t *rx_frame, uint8_t *tx_buffer, uint16_t *tx_len, uint8_t *rx_buffer, uint16_t *rx_len) {
    memcpy(tx_frame->p_inf, (uint8_t[]){0x00, 0xB0, 0x00, 0x00, len}, 5);
    tx_frame->inf_size = 5;

    if (!nfc_14a_encode_frame(tx_frame, tx_buffer, tx_len)) return false;
    uint8_t status = pcd_14a_reader_bytes_transfer(PCD_TRANSCEIVE, tx_buffer, *tx_len, rx_buffer, rx_len, U8ARR_BIT_LEN(*rx_len));
    if (status != STATUS_HF_TAG_OK) return false;
    if (!nfc_tag_14a_checks_crc(rx_buffer, *rx_len)) return false;
    *rx_len -= 2; // we don't care CRC
    if (!nfc_14a_decode_frame(rx_buffer, *rx_len, rx_frame)) return false;
    tx_frame->pcb_info->block_num ^= 1;
    if (rx_frame->p_inf[rx_frame->inf_size-2] == 0x90 && rx_frame->p_inf[rx_frame->inf_size-1] == 0x00) {
        return true;
    } else {
        return false;
    }
}

bool fmcos_clone_select_file(uint16_t df_idx, nfc_14a_frame_t *tx_frame, nfc_14a_frame_t *rx_frame, uint8_t *tx_buffer, uint16_t *tx_len, uint8_t *rx_buffer, uint16_t *rx_len) {
    uint8_t *inf_buffer = tx_frame->p_inf;

    memcpy(inf_buffer, (uint8_t[]){0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00}, 7);
    inf_buffer[5] = df_idx >> 8;
    inf_buffer[6] = df_idx & 0xFF;
    tx_frame->inf_size = 7;

    if (!nfc_14a_encode_frame(tx_frame, tx_buffer, tx_len)) return false;
    uint8_t status = pcd_14a_reader_bytes_transfer(PCD_TRANSCEIVE, tx_buffer, *tx_len, rx_buffer, rx_len, U8ARR_BIT_LEN(*rx_len));
    if (status != STATUS_HF_TAG_OK) return false;

    if (!nfc_tag_14a_checks_crc(rx_buffer, *rx_len)) return false;
    *rx_len -= 2; // we don't care CRC
    if (!nfc_14a_decode_frame(rx_buffer, *rx_len, rx_frame)) return false;
    tx_frame->pcb_info->block_num ^= 1;
    if (rx_frame->p_inf[rx_frame->inf_size-2] == 0x90 && rx_frame->p_inf[rx_frame->inf_size-1] == 0x00) {
        return true;
    } else {
        return false;
    }
}

bool fmcos_clone_zjzy(nfc_tag_fmcos_information_t * tag_info) {
    static uint8_t tx_buffer[NFC_TAG_FMCOS_MAX_RESP_SIZE];
    static uint16_t tx_len = 0;
    static uint8_t tx_inf_buffer[NFC_TAG_FMCOS_MAX_RESP_SIZE];
    static uint8_t rx_buffer[NFC_TAG_FMCOS_MAX_RESP_SIZE];
    static uint16_t rx_len = 0;

    
    // show progress by LED
    uint32_t *led_array = hw_get_led_array();
    for (int i = 0; i < RGB_LIST_NUM; i++) {
        nrf_gpio_pin_clear(led_array[i]);
    }
    set_slot_light_color(RGB_MAGENTA);

    // below are not static to reset block_num each time
    nfc_14a_pcb_info_t tx_pcb = {
        .has_cid = false,
        .has_nad = false,
        .block_num = 1 // is this one?
    };
    nfc_14a_frame_t tx_frame = {
        .pcb_info = &tx_pcb,
        .inf_size = 0,
        .p_inf = tx_inf_buffer
    };
    nfc_14a_pcb_info_t rx_pcb = {
        .has_cid = false,
        .has_nad = false,
        .block_num = 1 // is this one?
    };
    nfc_14a_frame_t rx_frame = {
        .pcb_info = &rx_pcb,
        .inf_size = 0,
        .p_inf = tx_inf_buffer
    };

    bool ok = fmcos_clone_select_file(0x3F00, &tx_frame, &rx_frame, tx_buffer, &tx_len, rx_buffer, &rx_len);
    if (ok) {
        fmcos_add_file(tag_info, 0x3F00, 0xFFFF, NFC_TAG_FMCOS_FILE_TYPE_DIR_FCI, rx_frame.p_inf, rx_frame.inf_size);
        fmcos_add_file(tag_info, 0x3F00, 0xFFFE, NFC_TAG_FMCOS_FILE_TYPE_DIR_NAME, (uint8_t[]){"1PAY.SYS.DDF01"}, 14);
    } else return false;

    nrf_gpio_pin_set(led_array[2]);

    ok = fmcos_clone_select_file(0x7F03, &tx_frame, &rx_frame, tx_buffer, &tx_len, rx_buffer, &rx_len);
    if (ok) {
        fmcos_add_file(tag_info, 0x7F03, 0xFFFF, NFC_TAG_FMCOS_FILE_TYPE_DIR_FCI, rx_frame.p_inf, rx_frame.inf_size);
        fmcos_add_file(tag_info, 0x7F03, 0xFFFE, NFC_TAG_FMCOS_FILE_TYPE_DIR_NAME, (uint8_t[]){0xD5, 0xFD, 0xD4, 0xAA, 0xD6, 0xC7, 0xBB, 0xDB, 0xD2, 0xD7, 0xCD, 0xA8, 0x15, 0x01}, 14);
    } else return false;

    nrf_gpio_pin_set(led_array[3]);

    // 7F03/0001, le=0x40
    ok = fmcos_clone_select_file(0x0001, &tx_frame, &rx_frame, tx_buffer, &tx_len, rx_buffer, &rx_len);
    if (!ok) return false;
    ok = fmcos_clone_read_binary_file(0x40, &tx_frame, &rx_frame, tx_buffer, &tx_len, rx_buffer, &rx_len);
    if (!ok) return false;
    fmcos_add_file(tag_info, 0x7F03, 0x0001, NFC_TAG_FMCOS_FILE_TYPE_BINARY, rx_frame.p_inf, rx_frame.inf_size);

    nrf_gpio_pin_set(led_array[4]);

    // 7F03/0015, le=0x60
    ok = fmcos_clone_select_file(0x0015, &tx_frame, &rx_frame, tx_buffer, &tx_len, rx_buffer, &rx_len);
    if (!ok) return false;
    ok = fmcos_clone_read_binary_file(0x60, &tx_frame, &rx_frame, tx_buffer, &tx_len, rx_buffer, &rx_len);
    if (!ok) return false;
    fmcos_add_file(tag_info, 0x7F03, 0x0015, NFC_TAG_FMCOS_FILE_TYPE_BINARY, rx_frame.p_inf, rx_frame.inf_size);

    nrf_gpio_pin_set(led_array[5]);

    // 7F03/0016, le=0x60
    ok = fmcos_clone_select_file(0x0016, &tx_frame, &rx_frame, tx_buffer, &tx_len, rx_buffer, &rx_len);
    if (!ok) return false;
    ok = fmcos_clone_read_binary_file(0x60, &tx_frame, &rx_frame, tx_buffer, &tx_len, rx_buffer, &rx_len);
    if (!ok) return false;
    fmcos_add_file(tag_info, 0x7F03, 0x0016, NFC_TAG_FMCOS_FILE_TYPE_BINARY, rx_frame.p_inf, rx_frame.inf_size);

    nrf_gpio_pin_set(led_array[6]);

    // 7F03/0019, le=0x40
    ok = fmcos_clone_select_file(0x0019, &tx_frame, &rx_frame, tx_buffer, &tx_len, rx_buffer, &rx_len);
    if (!ok) return false;
    ok = fmcos_clone_read_binary_file(0x40, &tx_frame, &rx_frame, tx_buffer, &tx_len, rx_buffer, &rx_len);
    if (!ok) return false;
    fmcos_add_file(tag_info, 0x7F03, 0x0019, NFC_TAG_FMCOS_FILE_TYPE_BINARY, rx_frame.p_inf, rx_frame.inf_size);

    nrf_gpio_pin_set(led_array[7]);

    // reset lights
    set_slot_light_color(RGB_GREEN);
    for (int i = 0; i < RGB_LIST_NUM; i++) {
        nrf_gpio_pin_clear(led_array[i]);
    }
    return true;
}

bool nfc_tag_fmcos_clone(tag_specific_type_t type, tag_data_buffer_t *buffer) {
    int info_size = sizeof(nfc_tag_fmcos_information_t);
    nfc_tag_fmcos_information_t * tag_info;
    if (buffer->length >= info_size) {
        tag_info = (nfc_tag_fmcos_information_t *)buffer->buffer;
    } else {
        return false;
    }
    bool is_reader_mode_now = get_device_mode() == DEVICE_MODE_READER;
    if (!is_reader_mode_now) {
        // finish HF reader initialization
        pcd_14a_reader_reset();
    }
    pcd_14a_reader_antenna_on();
    bsp_delay_ms(8);
    // select a tag
    picc_14a_tag_t tag;

    bool hf_copy_succeeded = false;
    uint8_t status = pcd_14a_reader_scan_auto(&tag);
    // above does pcd_14a_reader_ats_request()
    // FSD=256, FSDI=8, CID=0
    if (status == STATUS_HF_TAG_OK) {
        // copy uid
        tag_info->res_coll.size = tag.uid_len;
        memcpy(tag_info->res_coll.uid, tag.uid, tag.uid_len);
        // copy atqa
        memcpy(tag_info->res_coll.atqa, tag.atqa, 2);
        // copy sak
        tag_info->res_coll.sak[0] = tag.sak;
        // copy ats
        tag_info->res_coll.ats.length = tag.ats_len;
        memcpy(tag_info->res_coll.ats.data, tag.ats, tag.ats_len);
        NRF_LOG_INFO("Offline HF uid copied")

        if (type == TAG_TYPE_FMCOS_ZJZY) {
            hf_copy_succeeded = fmcos_clone_zjzy(tag_info);
        } else { // else if (type == TAG_TYPE_FMCOS_GENERIC) {
            hf_copy_succeeded = true;
        }
    } else {
        NRF_LOG_INFO("No HF tag found");
    }

    pcd_14a_reader_antenna_off();
    return hf_copy_succeeded;
}