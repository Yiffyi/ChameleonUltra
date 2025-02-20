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

// Factory data for initialization of FMCOS
bool nfc_tag_fmcos_data_factory(uint8_t slot, tag_specific_type_t tag_type) {
    nfc_tag_fmcos_file_container_t mf = {
        .file_id = 0x3f00,
        .file_type = NFC_TAG_FMCOS_FILE_TYPE_DIR,
        .value_size = 0
    };

    nfc_tag_fmcos_information_t fmcos_tmp_info;
    nfc_tag_fmcos_information_t *p_fmcos_info;

    memcpy(p_fmcos_info->memory, &mf, sizeof(mf));

    p_fmcos_info->config.mode_write = NFC_TAG_MF1_WRITE_IGNORE;

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
