#ifndef NFC_FMCOS_H
#define NFC_FMCOS_H

#include "nfc_14a.h"

#define NFC_TAG_FMCOS_MEM_SIZE 4096

typedef enum {
    NFC_TAG_MF1_WRITE_DENIED    =   0u,
    NFC_TAG_MF1_WRITE_IGNORE    =   1u,
    NFC_TAG_MF1_WRITE_SHADOW    =   2u,
    NFC_TAG_MF1_WRITE_NORMAL    =   3u,
} nfc_tag_fmcos_write_mode_t;

// FMCOS configuration
typedef struct {
    /**
     * Normal write mode (write normally according to the current state, affected by the control bit and the back door card)
     * Deny write mode (similar to control bit lock, directly reject any write, return nack)
     * Fraudulent writing mode (on the surface, returning ack indicates that the writing is successful, but in fact, even RAM is not written)
     * Shadow write mode (write to RAM, and return ack to indicate success, but not save to flash)
     *  @see nfc_tag_mf1_write_mode_t
     */
    nfc_tag_fmcos_write_mode_t mode_write;
} nfc_tag_fmcos_configure_t;

typedef enum nfc_tag_fmcos_file_type {
    NFC_TAG_FMCOS_FILE_TYPE_DIR     = (uint8_t)1,
    NFC_TAG_FMCOS_FILE_TYPE_BINARY,
} nfc_tag_fmcos_file_type_t;

typedef struct {
    uint16_t file_id;
    nfc_tag_fmcos_file_type_t file_type;

    uint8_t value_size;
    uint8_t value[];
} nfc_tag_fmcos_file_container_t;

typedef struct __attribute__((aligned(4))) {
    nfc_tag_14a_coll_res_entity_t res_coll;
    nfc_tag_fmcos_configure_t config;
    uint8_t memory[NFC_TAG_FMCOS_MEM_SIZE];
} nfc_tag_fmcos_information_t;

int nfc_tag_fmcos_data_loadcb(tag_specific_type_t type, tag_data_buffer_t *buffer);
int nfc_tag_fmcos_data_savecb(tag_specific_type_t type, tag_data_buffer_t *buffer);
bool nfc_tag_fmcos_data_factory(uint8_t slot, tag_specific_type_t tag_type);
#endif