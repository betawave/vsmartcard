/*
 * Copyright (C) 2011 Frank Morgner
 *
 * This file is part of ccid.
 *
 * ccid is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * ccid is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ccid.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "npa.h"
#include "scutil.h"
#include "sm.h"
#include "sslutil.h"
#include <eac/cv_cert.h>
#include <eac/eac.h>
#include <eac/pace.h>
#include <eac/ca.h>
#include <eac/ta.h>
#include <libopensc/asn1.h>
#include <libopensc/log.h>
#include <libopensc/opensc.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <string.h>


#define ASN1_APP_IMP_OPT(stname, field, type, tag) ASN1_EX_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION|ASN1_TFLG_OPTIONAL, tag, stname, field, type)
#define ASN1_APP_IMP(stname, field, type, tag) ASN1_EX_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION, tag, stname, field, type)
IMPLEMENT_ASN1_FUNCTIONS(CVC_DISCRETIONARY_DATA_TEMPLATES)

/*
 * MSE:Set AT
 */

typedef struct npa_mse_cd_st {
    ASN1_OBJECT *cryptographic_mechanism_reference;
    ASN1_OCTET_STRING *key_reference1;
    ASN1_OCTET_STRING *key_reference2;
    ASN1_OCTET_STRING *eph_pub_key;
    CVC_DISCRETIONARY_DATA_TEMPLATES *auxiliary_data;
    CVC_CHAT *chat;
} NPA_MSE_C;
ASN1_SEQUENCE(NPA_MSE_C) = {
    /* 0x80
     * Cryptographic mechanism reference */
    ASN1_IMP_OPT(NPA_MSE_C, cryptographic_mechanism_reference, ASN1_OBJECT, 0),
    /* 0x83
     * Reference of a public key / secret key */
    ASN1_IMP_OPT(NPA_MSE_C, key_reference1, ASN1_OCTET_STRING, 3),
    /* 0x84
     * Reference of a private key / Reference for computing a session key */
    ASN1_IMP_OPT(NPA_MSE_C, key_reference2, ASN1_OCTET_STRING, 4),
    /* 0x91
     * Ephemeral Public Key */
    ASN1_IMP_OPT(NPA_MSE_C, eph_pub_key, ASN1_OCTET_STRING, 0x11),
    /* 0x67
     * Auxiliary authenticated data */
    ASN1_APP_IMP_OPT(NPA_MSE_C, auxiliary_data, CVC_DISCRETIONARY_DATA_TEMPLATES, 7),
    /*ASN1_APP_IMP_OPT(NPA_MSE_C, auxiliary_data, ASN1_OCTET_STRING, 7),*/
    /* Certificate Holder Authorization Template */
    ASN1_OPT(NPA_MSE_C, chat, CVC_CHAT),
} ASN1_SEQUENCE_END(NPA_MSE_C)
DECLARE_ASN1_FUNCTIONS(NPA_MSE_C)
IMPLEMENT_ASN1_FUNCTIONS(NPA_MSE_C)


/*
 * General Authenticate for PACE
 */

/* Protocol Command Data */
typedef struct npa_gen_auth_pace_cd_st {
    ASN1_OCTET_STRING *mapping_data;
    ASN1_OCTET_STRING *eph_pub_key;
    ASN1_OCTET_STRING *auth_token;
} NPA_GEN_AUTH_PACE_C_BODY;
ASN1_SEQUENCE(NPA_GEN_AUTH_PACE_C_BODY) = {
    /* 0x81
     * Mapping Data */
    ASN1_IMP_OPT(NPA_GEN_AUTH_PACE_C_BODY, mapping_data, ASN1_OCTET_STRING, 1),
    /* 0x83
     * Ephemeral Public Key */
    ASN1_IMP_OPT(NPA_GEN_AUTH_PACE_C_BODY, eph_pub_key, ASN1_OCTET_STRING, 3),
    /* 0x85
     * Authentication Token */
    ASN1_IMP_OPT(NPA_GEN_AUTH_PACE_C_BODY, auth_token, ASN1_OCTET_STRING, 5),
} ASN1_SEQUENCE_END(NPA_GEN_AUTH_PACE_C_BODY)
DECLARE_ASN1_FUNCTIONS(NPA_GEN_AUTH_PACE_C_BODY)
IMPLEMENT_ASN1_FUNCTIONS(NPA_GEN_AUTH_PACE_C_BODY)

typedef NPA_GEN_AUTH_PACE_C_BODY NPA_GEN_AUTH_PACE_C;
/* 0x7C
 * Dynamic Authentication Data */
ASN1_ITEM_TEMPLATE(NPA_GEN_AUTH_PACE_C) =
    ASN1_EX_TEMPLATE_TYPE(
            ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION,
            0x1c, NPA_GEN_AUTH_PACE_C, NPA_GEN_AUTH_PACE_C_BODY)
ASN1_ITEM_TEMPLATE_END(NPA_GEN_AUTH_PACE_C)
DECLARE_ASN1_FUNCTIONS(NPA_GEN_AUTH_PACE_C)
IMPLEMENT_ASN1_FUNCTIONS(NPA_GEN_AUTH_PACE_C)

/* Protocol Response Data */
typedef struct npa_gen_auth_pace_rapdu_body_st {
    ASN1_OCTET_STRING *enc_nonce;
    ASN1_OCTET_STRING *mapping_data;
    ASN1_OCTET_STRING *eph_pub_key;
    ASN1_OCTET_STRING *auth_token;
    ASN1_OCTET_STRING *cur_car;
    ASN1_OCTET_STRING *prev_car;
} NPA_GEN_AUTH_PACE_R_BODY;
ASN1_SEQUENCE(NPA_GEN_AUTH_PACE_R_BODY) = {
    /* 0x80
     * Encrypted Nonce */
    ASN1_IMP_OPT(NPA_GEN_AUTH_PACE_R_BODY, enc_nonce, ASN1_OCTET_STRING, 0),
    /* 0x82
     * Mapping Data */
    ASN1_IMP_OPT(NPA_GEN_AUTH_PACE_R_BODY, mapping_data, ASN1_OCTET_STRING, 2),
    /* 0x84
     * Ephemeral Public Key */
    ASN1_IMP_OPT(NPA_GEN_AUTH_PACE_R_BODY, eph_pub_key, ASN1_OCTET_STRING, 4),
    /* 0x86
     * Authentication Token */
    ASN1_IMP_OPT(NPA_GEN_AUTH_PACE_R_BODY, auth_token, ASN1_OCTET_STRING, 6),
    /* 0x87
     * Most recent Certification Authority Reference */
    ASN1_IMP_OPT(NPA_GEN_AUTH_PACE_R_BODY, cur_car, ASN1_OCTET_STRING, 7),
    /* 0x88
     * Previous Certification Authority Reference */
    ASN1_IMP_OPT(NPA_GEN_AUTH_PACE_R_BODY, prev_car, ASN1_OCTET_STRING, 8),
} ASN1_SEQUENCE_END(NPA_GEN_AUTH_PACE_R_BODY)
DECLARE_ASN1_FUNCTIONS(NPA_GEN_AUTH_PACE_R_BODY)
IMPLEMENT_ASN1_FUNCTIONS(NPA_GEN_AUTH_PACE_R_BODY)

typedef NPA_GEN_AUTH_PACE_R_BODY NPA_GEN_AUTH_PACE_R;
/* 0x7C
 * Dynamic Authentication Data */
ASN1_ITEM_TEMPLATE(NPA_GEN_AUTH_PACE_R) =
    ASN1_EX_TEMPLATE_TYPE(
            ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION,
            0x1c, NPA_GEN_AUTH_PACE_R, NPA_GEN_AUTH_PACE_R_BODY)
ASN1_ITEM_TEMPLATE_END(NPA_GEN_AUTH_PACE_R)
DECLARE_ASN1_FUNCTIONS(NPA_GEN_AUTH_PACE_R)
IMPLEMENT_ASN1_FUNCTIONS(NPA_GEN_AUTH_PACE_R)


/*
 * General Authenticate for CA
 */

/* Protocol Command Data */
typedef struct npa_gen_auth_ca_cd_st {
    ASN1_OCTET_STRING *eph_pub_key;
} NPA_GEN_AUTH_CA_C_BODY;
ASN1_SEQUENCE(NPA_GEN_AUTH_CA_C_BODY) = {
    /* 0x80
     * Ephemeral Public Key */
    ASN1_IMP_OPT(NPA_GEN_AUTH_CA_C_BODY, eph_pub_key, ASN1_OCTET_STRING, 0),
} ASN1_SEQUENCE_END(NPA_GEN_AUTH_CA_C_BODY)
DECLARE_ASN1_FUNCTIONS(NPA_GEN_AUTH_CA_C_BODY)
IMPLEMENT_ASN1_FUNCTIONS(NPA_GEN_AUTH_CA_C_BODY)

typedef NPA_GEN_AUTH_CA_C_BODY NPA_GEN_AUTH_CA_C;
/* 0x7C
 * Dynamic Authentication Data */
ASN1_ITEM_TEMPLATE(NPA_GEN_AUTH_CA_C) =
    ASN1_EX_TEMPLATE_TYPE(
            ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION,
            0x1c, NPA_GEN_AUTH_CA_C, NPA_GEN_AUTH_CA_C_BODY)
ASN1_ITEM_TEMPLATE_END(NPA_GEN_AUTH_CA_C)
DECLARE_ASN1_FUNCTIONS(NPA_GEN_AUTH_CA_C)
IMPLEMENT_ASN1_FUNCTIONS(NPA_GEN_AUTH_CA_C)

/* Protocol Response Data */
typedef struct npa_gen_auth_ca_rapdu_body_st {
    ASN1_OCTET_STRING *nonce;
    ASN1_OCTET_STRING *auth_token;
} NPA_GEN_AUTH_CA_R_BODY;
ASN1_SEQUENCE(NPA_GEN_AUTH_CA_R_BODY) = {
    /* 0x81
     * Nonce */
    ASN1_IMP_OPT(NPA_GEN_AUTH_CA_R_BODY, nonce, ASN1_OCTET_STRING, 1),
    /* 0x82
     * Authentication Token */
    ASN1_IMP_OPT(NPA_GEN_AUTH_CA_R_BODY, auth_token, ASN1_OCTET_STRING, 2),
} ASN1_SEQUENCE_END(NPA_GEN_AUTH_CA_R_BODY)
DECLARE_ASN1_FUNCTIONS(NPA_GEN_AUTH_CA_R_BODY)
IMPLEMENT_ASN1_FUNCTIONS(NPA_GEN_AUTH_CA_R_BODY)

typedef NPA_GEN_AUTH_CA_R_BODY NPA_GEN_AUTH_CA_R;
/* 0x7C
 * Dynamic Authentication Data */
ASN1_ITEM_TEMPLATE(NPA_GEN_AUTH_CA_R) =
    ASN1_EX_TEMPLATE_TYPE(
            ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION,
            0x1c, NPA_GEN_AUTH_CA_R, NPA_GEN_AUTH_CA_R_BODY)
ASN1_ITEM_TEMPLATE_END(NPA_GEN_AUTH_CA_R)
DECLARE_ASN1_FUNCTIONS(NPA_GEN_AUTH_CA_R)
IMPLEMENT_ASN1_FUNCTIONS(NPA_GEN_AUTH_CA_R)



#define maxresp SC_MAX_APDU_BUFFER_SIZE - 2

#define NPA_FLAG_DISABLE_CHECKS 1
/** NPA secure messaging context */
struct npa_sm_ctx {
    /** Send sequence counter */
    BIGNUM *ssc;
    /** EAC context */
    EAC_CTX *ctx;
    /** Certificate Description given on initialization of PACE */
    BUF_MEM *certificate_description;
    /** picc's compressed ephemeral public key of PACE */
    BUF_MEM *id_icc;
    /** PCD's compressed ephemeral public key of CA */
    BUF_MEM *eph_pub_key;
    /** Auxiliary Data */
    BUF_MEM *auxiliary_data;
    char flags;
};


/* included in OpenPACE, but not propagated */
extern BUF_MEM *BUF_MEM_create(size_t len);
extern BUF_MEM *BUF_MEM_create_init(const void *buf, size_t len);


static int npa_sm_encrypt(sc_card_t *card, const struct sm_ctx *ctx,
        const u8 *data, size_t datalen, u8 **enc);
static int npa_sm_decrypt(sc_card_t *card, const struct sm_ctx *ctx,
        const u8 *enc, size_t enclen, u8 **data);
static int npa_sm_authenticate(sc_card_t *card, const struct sm_ctx *ctx,
        const u8 *data, size_t datalen, u8 **outdata);
static int npa_sm_verify_authentication(sc_card_t *card, const struct sm_ctx *ctx,
        const u8 *mac, size_t maclen,
        const u8 *macdata, size_t macdatalen);
static int npa_sm_pre_transmit(sc_card_t *card, const struct sm_ctx *ctx,
        sc_apdu_t *apdu);
static int npa_sm_post_transmit(sc_card_t *card, const struct sm_ctx *ctx,
        sc_apdu_t *sm_apdu);
static int npa_sm_finish(sc_card_t *card, const struct sm_ctx *ctx,
        sc_apdu_t *apdu);
static void npa_sm_clear_free(const struct sm_ctx *ctx);

static int increment_ssc(struct npa_sm_ctx *eacsmctx);
static int decrement_ssc(struct npa_sm_ctx *eacsmctx);
static int reset_ssc(struct npa_sm_ctx *eacsmctx);

static struct npa_sm_ctx *
npa_sm_ctx_create(EAC_CTX *ctx, const unsigned char *certificate_description,
        size_t certificate_description_length,
        const unsigned char *id_icc, size_t id_icc_length)
{
    struct npa_sm_ctx *out = malloc(sizeof *out);
    if (!out)
        goto err;

    out->ssc = BN_new();
    if (!out->ssc || reset_ssc(out) < 0)
        goto err;

    out->ctx = ctx;

    if (certificate_description && certificate_description_length) {
        out->certificate_description =
            BUF_MEM_create_init(certificate_description,
                    certificate_description_length);
        if (!out->certificate_description)
            goto err;
    } else
        out->certificate_description = NULL;

    out->id_icc = BUF_MEM_create_init(id_icc, id_icc_length);
    if (!out->id_icc)
        goto err;

    out->eph_pub_key = NULL;
    out->auxiliary_data = NULL;

    out->flags = NPA_FLAG_DISABLE_CHECKS;

    return out;

err:
    if (out) {
        if (out->ssc)
            BN_clear_free(out->ssc);
        free(out);
    }
    return NULL;
}


int GetReadersPACECapabilities(u8 *bitmap)
{
    if (!bitmap)
        return SC_ERROR_INVALID_ARGUMENTS;

    /* BitMap */
    *bitmap = NPA_BITMAP_PACE|NPA_BITMAP_EID|NPA_BITMAP_ESIGN;

    return SC_SUCCESS;
}

#define ISO_READ_BINARY  0xB0
#define ISO_P1_FLAG_SFID 0x80
/** Read an EF.
 * @note MF must be selected before calling this function.
 * */
static int get_ef(struct sm_ctx *npactx, sc_card_t *card, unsigned char sfid,
        u8 **ef, size_t *ef_len)
{
    int r;
    /* we read less bytes than possible. this is a workaround for acr 122,
     * which only supports apdus of max 250 bytes */
    size_t read = maxresp - 8;
    u8 p2;
    sc_apdu_t apdu;
    sc_file_t *file = NULL;
    u8 *p;

    if (!card || !ef || !ef_len) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }
    *ef_len = 0;

    if (read > SC_MAX_APDU_BUFFER_SIZE - 2)
        sc_format_apdu(card, &apdu, SC_APDU_CASE_2_EXT,
                ISO_READ_BINARY, ISO_P1_FLAG_SFID|sfid, 0);
    else
        sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT,
                ISO_READ_BINARY, ISO_P1_FLAG_SFID|sfid, 0);

    p = realloc(*ef, read);
    if (!p) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    *ef = p;
    apdu.resp = *ef;
    apdu.resplen = read;
    apdu.le = read;

    if (!npactx)
        r = sc_transmit_apdu(card, &apdu);
    else
        r = sm_transmit_apdu(npactx, card, &apdu);
    /* emulate the behaviour of sc_read_binary */
    if (r >= 0)
        r = apdu.resplen;

    while(1) {
        if (r >= 0 && r != read) {
            *ef_len += r;
            break;
        }
        if (r < 0) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not read EF.");
            goto err;
        }
        *ef_len += r;

        p = realloc(*ef, *ef_len + read);
        if (!p) {
            r = SC_ERROR_OUT_OF_MEMORY;
            goto err;
        }
        *ef = p;

        if (!npactx)
            r = sc_read_binary(card, *ef_len,
                    *ef + *ef_len, read, 0);
        else {
            if (*ef_len > 0x7fff) {
                r = SC_ERROR_OFFSET_TOO_LARGE;
                goto err;
            }
            apdu.p1 = (*ef_len >> 8) & 0x7F;
            apdu.p2 = *ef_len & 0xFF;
            apdu.resp = *ef + *ef_len;
            r = sm_transmit_apdu(npactx, card, &apdu);
            /* emulate the behaviour of sc_read_binary */
            if (r >= 0)
                r = apdu.resplen;
        }
    }

    /* test cards only return an empty FCI template,
     * so we can't determine any file proberties */
    if (file && *ef_len < file->size) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Actual filesize differs from the size in file "
                "proberties (%u!=%u).", *ef_len, file->size);
        r = SC_ERROR_FILE_TOO_SMALL;
        goto err;
    }

    r = SC_SUCCESS;

err:
    free(file);

    return r;
}

int get_ef_card_access(struct sm_ctx *oldnpactx, sc_card_t *card,
        u8 **ef_cardaccess, size_t *length_ef_cardaccess)
{
    return get_ef(oldnpactx, card, SFID_EF_CARDACCESS, ef_cardaccess, length_ef_cardaccess);
}

static int format_mse_cdata(struct sc_context *ctx, int protocol,
        const unsigned char *key_reference1, size_t key_reference1_len,
        const unsigned char *key_reference2, size_t key_reference2_len,
        const unsigned char *eph_pub_key, size_t eph_pub_key_len,
        const unsigned char *auxiliary_data, size_t auxiliary_data_len,
        const CVC_CHAT *chat, unsigned char **cdata)
{
    NPA_MSE_C *data = NULL;
    unsigned char *data_sequence = NULL;
    const unsigned char *data_no_sequence;
    unsigned char *p;
    long length;
    int r, class, tag;

    if (!cdata) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }

    data = NPA_MSE_C_new();
    if (!data) {
        goto err;
    }

    if (protocol) {
        data->cryptographic_mechanism_reference = OBJ_nid2obj(protocol);
        if (!data->cryptographic_mechanism_reference) {
            sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Error setting Cryptographic mechanism reference of MSE:Set AT data");
            r = SC_ERROR_INTERNAL;
            goto err;
        }
    }

    if (key_reference1 && key_reference1_len) {
        data->key_reference1 = ASN1_OCTET_STRING_new();
        if (!data->key_reference1
                || !M_ASN1_OCTET_STRING_set(
                    data->key_reference1, key_reference1, key_reference1_len)) {
            sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Error setting key reference 1 of MSE:Set AT data");
            r = SC_ERROR_INTERNAL;
            goto err;
        }
    }

    if (key_reference2 && key_reference2_len) {
        data->key_reference2 = ASN1_OCTET_STRING_new();
        if (!data->key_reference2
                || !M_ASN1_OCTET_STRING_set(
                    data->key_reference2, key_reference2, key_reference2_len)) {
            sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Error setting key reference 2 of MSE:Set AT data");
            r = SC_ERROR_INTERNAL;
            goto err;
        }
    }

    if (eph_pub_key && eph_pub_key_len) {
        data->eph_pub_key = ASN1_OCTET_STRING_new();
        if (!data->eph_pub_key
                || !M_ASN1_OCTET_STRING_set(
                    data->eph_pub_key, eph_pub_key, eph_pub_key_len)) {
            sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Error setting ephemeral Public Key of MSE:Set AT data");
            r = SC_ERROR_INTERNAL;
            goto err;
        }
    }

    if (auxiliary_data && auxiliary_data_len) {
        if (!d2i_CVC_DISCRETIONARY_DATA_TEMPLATES(&data->auxiliary_data, &auxiliary_data, auxiliary_data_len)) {
            sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Error setting auxiliary authenticated data of MSE:Set AT data");
            r = SC_ERROR_INTERNAL;
            goto err;
        }
    }

    data->chat = (CVC_CHAT *) chat;


    length = i2d_NPA_MSE_C(data, &data_sequence);
    data_no_sequence = data_sequence;
    if (length < 0
            || (0x80 & ASN1_get_object(&data_no_sequence, &length, &tag, &class, length))) {
        sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Error encoding MSE:Set AT APDU data");
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    if (length < 0) {
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    bin_log(ctx, SC_LOG_DEBUG_NORMAL, "MSE command data", data_no_sequence, length);


    p = realloc(*cdata, length);
    if (!p) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    memcpy(p, data_no_sequence, length);
    *cdata = p;
    r = length;

err:
    if (data) {
        /* do not free the functions parameter chat */
        data->chat = NULL;
        NPA_MSE_C_free(data);
    }
    free(data_sequence);

    return r;
}

#define ISO_MSE 0x22
static int npa_mse(struct sm_ctx *oldnpactx, sc_card_t *card, unsigned char p1,
        int protocol, const unsigned char *key_reference1,
        size_t key_reference1_len, const unsigned char *key_reference2,
        size_t key_reference2_len, const unsigned char *auxiliary_data,
        size_t auxiliary_data_len, const CVC_CHAT *chat, u8 *sw1, u8 *sw2)
{
    sc_apdu_t apdu;
    unsigned char *d = NULL;
    int r, tries, class, tag;

    if (!card) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }

    sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, ISO_MSE, p1, 0xa4);
    
    r = format_mse_cdata(card->ctx, protocol, key_reference1,
            key_reference1_len, key_reference2, key_reference2_len, NULL, 0,
            auxiliary_data, auxiliary_data_len, chat, &d);
    if (r < 0)
        goto err;
    apdu.data = d;
    apdu.datalen = r;
    apdu.lc = r;


    if (oldnpactx)
        r = sm_transmit_apdu(oldnpactx, card, &apdu);
    else
        r = sc_transmit_apdu(card, &apdu);
    if (r < 0)
        goto err;

    if (apdu.resplen) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "MSE:Set AT response data should be empty "
                "(contains %u bytes)", apdu.resplen);
        r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
        goto err;
    }

    if (sw1)
        *sw1 = apdu.sw1;
    if (sw2)
        *sw2 = apdu.sw2;

err:
    free(d);

    return r;
}

static int npa_mse_set_at_pace(struct sm_ctx *oldnpactx, sc_card_t *card,
        int protocol, enum s_type secret_key, const CVC_CHAT *chat, u8 *sw1,
        u8 *sw2)
{
    int r, tries;
    char key = secret_key;
   
    r = npa_mse(oldnpactx, card, 0xC1, protocol, &key, sizeof key, NULL, 0, NULL, 0, chat, sw1, sw2);

    if (*sw1 == 0x63) {
        if ((*sw2 & 0xc0) == 0xc0) {
            tries = *sw2 & 0x0f;
            if (tries <= 1) {
                /* this is only a warning... */
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Remaining tries: %d (%s must be %s)\n",
                        tries, npa_secret_name(secret_key),
                        tries ? "resumed" : "unblocked");
            }
            r = SC_SUCCESS;
        } else {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Unknown status bytes: SW1=%02X, SW2=%02X\n",
                    *sw1, *sw2);
            r = SC_ERROR_CARD_CMD_FAILED;
        }
    } else if (*sw1 == 0x62 && *sw2 == 0x83) {
             sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Password is deactivated\n");
             r = SC_ERROR_AUTH_METHOD_BLOCKED;
    } else {
        r = sc_check_sw(card, *sw1, *sw2);
    }

    return r;
}


#define ISO_GENERAL_AUTHENTICATE 0x86
#define ISO_COMMAND_CHAINING 0x10
static int npa_gen_auth_1_encrypted_nonce(struct sm_ctx *oldnpactx,
        sc_card_t *card, u8 **enc_nonce, size_t *enc_nonce_len)
{
    sc_apdu_t apdu;
    NPA_GEN_AUTH_PACE_C *c_data = NULL;
    NPA_GEN_AUTH_PACE_R *r_data = NULL;
    unsigned char *d = NULL, *p;
    int r, l;
	unsigned char resp[maxresp];

    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, ISO_GENERAL_AUTHENTICATE,
            0, 0);
    apdu.cla = ISO_COMMAND_CHAINING;

    c_data = NPA_GEN_AUTH_PACE_C_new();
    if (!c_data) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    r = i2d_NPA_GEN_AUTH_PACE_C(c_data, &d);
    if (r < 0) {
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    apdu.data = (const u8 *) d;
    apdu.datalen = r;
    apdu.lc = r;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Encrypted Nonce) command data", apdu.data, apdu.datalen);

    apdu.resplen = sizeof resp;
    apdu.resp = resp;
    if (oldnpactx)
        r = sm_transmit_apdu(oldnpactx, card, &apdu);
    else
        r = sc_transmit_apdu(card, &apdu);
    if (r < 0)
        goto err;

    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    if (r < 0)
        goto err;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Encrypted Nonce) response data", apdu.resp, apdu.resplen);

    if (!d2i_NPA_GEN_AUTH_PACE_R(&r_data,
                (const unsigned char **) &apdu.resp, apdu.resplen)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse general authenticate response data.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    if (!r_data->enc_nonce
            || r_data->mapping_data
            || r_data->eph_pub_key
            || r_data->auth_token
            || r_data->cur_car
            || r_data->prev_car) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Response data of general authenticate for "
                "step 1 should (only) contain the encrypted nonce.");
        r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
        goto err;
    }
    p = r_data->enc_nonce->data;
    l = r_data->enc_nonce->length;

    *enc_nonce = malloc(l);
    if (!*enc_nonce) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    /* Flawfinder: ignore */
    memcpy(*enc_nonce, p, l);
    *enc_nonce_len = l;

err:
    if (c_data)
        NPA_GEN_AUTH_PACE_C_free(c_data);
    free(d);
    if (r_data)
        NPA_GEN_AUTH_PACE_R_free(r_data);

    return r;
}
static int npa_gen_auth_2_map_nonce(struct sm_ctx *oldnpactx,
        sc_card_t *card, const u8 *in, size_t in_len, u8 **map_data_out,
        size_t *map_data_out_len)
{
    sc_apdu_t apdu;
    NPA_GEN_AUTH_PACE_C *c_data = NULL;
    NPA_GEN_AUTH_PACE_R *r_data = NULL;
    unsigned char *d = NULL, *p;
    int r, l;
	unsigned char resp[maxresp];

    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, ISO_GENERAL_AUTHENTICATE,
            0, 0);
    apdu.cla = ISO_COMMAND_CHAINING;

    c_data = NPA_GEN_AUTH_PACE_C_new();
    if (!c_data) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    c_data->mapping_data = ASN1_OCTET_STRING_new();
    if (!c_data->mapping_data
            || !M_ASN1_OCTET_STRING_set(
                c_data->mapping_data, in, in_len)) {
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    r = i2d_NPA_GEN_AUTH_PACE_C(c_data, &d);
    if (r < 0) {
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    apdu.data = (const u8 *) d;
    apdu.datalen = r;
    apdu.lc = r;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Map Nonce) command data", apdu.data, apdu.datalen);

    apdu.resplen = sizeof resp;
    apdu.resp = resp;
    if (oldnpactx)
        r = sm_transmit_apdu(oldnpactx, card, &apdu);
    else
        r = sc_transmit_apdu(card, &apdu);
    if (r < 0)
        goto err;

    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    if (r < 0)
        goto err;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Map Nonce) response data", apdu.resp, apdu.resplen);

    if (!d2i_NPA_GEN_AUTH_PACE_R(&r_data,
                (const unsigned char **) &apdu.resp, apdu.resplen)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse general authenticate response data.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    if (r_data->enc_nonce
            || !r_data->mapping_data
            || r_data->eph_pub_key
            || r_data->auth_token
            || r_data->cur_car
            || r_data->prev_car) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Response data of general authenticate for "
                "step 2 should (only) contain the mapping data.");
        r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
        goto err;
    }
    p = r_data->mapping_data->data;
    l = r_data->mapping_data->length;

    *map_data_out = malloc(l);
    if (!*map_data_out) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    /* Flawfinder: ignore */
    memcpy(*map_data_out, p, l);
    *map_data_out_len = l;

err:
    if (c_data)
        NPA_GEN_AUTH_PACE_C_free(c_data);
    free(d);
    if (r_data)
        NPA_GEN_AUTH_PACE_R_free(r_data);

    return r;
}
static int npa_gen_auth_3_perform_key_agreement(
        struct sm_ctx *oldnpactx, sc_card_t *card,
        const u8 *in, size_t in_len, u8 **eph_pub_key_out, size_t *eph_pub_key_out_len)
{
    sc_apdu_t apdu;
    NPA_GEN_AUTH_PACE_C *c_data = NULL;
    NPA_GEN_AUTH_PACE_R *r_data = NULL;
    unsigned char *d = NULL, *p;
    int r, l;
	unsigned char resp[maxresp];

    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, ISO_GENERAL_AUTHENTICATE,
            0, 0);
    apdu.cla = ISO_COMMAND_CHAINING;

    c_data = NPA_GEN_AUTH_PACE_C_new();
    if (!c_data) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    c_data->eph_pub_key = ASN1_OCTET_STRING_new();
    if (!c_data->eph_pub_key
            || !M_ASN1_OCTET_STRING_set(
                c_data->eph_pub_key, in, in_len)) {
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    r = i2d_NPA_GEN_AUTH_PACE_C(c_data, &d);
    if (r < 0) {
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    apdu.data = (const u8 *) d;
    apdu.datalen = r;
    apdu.lc = r;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Perform Key Agreement) command data", apdu.data, apdu.datalen);

    apdu.resplen = sizeof resp;
    apdu.resp = resp;
    if (oldnpactx)
        r = sm_transmit_apdu(oldnpactx, card, &apdu);
    else
        r = sc_transmit_apdu(card, &apdu);
    if (r < 0)
        goto err;

    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    if (r < 0)
        goto err;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Perform Key Agreement) response data", apdu.resp, apdu.resplen);

    if (!d2i_NPA_GEN_AUTH_PACE_R(&r_data,
                (const unsigned char **) &apdu.resp, apdu.resplen)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse general authenticate response data.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    if (r_data->enc_nonce
            || r_data->mapping_data
            || !r_data->eph_pub_key
            || r_data->auth_token
            || r_data->cur_car
            || r_data->prev_car) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Response data of general authenticate for "
                "step 3 should (only) contain the ephemeral public key.");
        r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
        goto err;
    }
    p = r_data->eph_pub_key->data;
    l = r_data->eph_pub_key->length;

    *eph_pub_key_out = malloc(l);
    if (!*eph_pub_key_out) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    /* Flawfinder: ignore */
    memcpy(*eph_pub_key_out, p, l);
    *eph_pub_key_out_len = l;

err:
    if (c_data)
        NPA_GEN_AUTH_PACE_C_free(c_data);
    free(d);
    if (r_data)
        NPA_GEN_AUTH_PACE_R_free(r_data);

    return r;
}
static int npa_gen_auth_4_mutual_authentication(
        struct sm_ctx *oldnpactx, sc_card_t *card,
        const u8 *in, size_t in_len, u8 **auth_token_out,
        size_t *auth_token_out_len, u8 **recent_car, size_t *recent_car_len,
        u8 **prev_car, size_t *prev_car_len)
{
    sc_apdu_t apdu;
    NPA_GEN_AUTH_PACE_C *c_data = NULL;
    NPA_GEN_AUTH_PACE_R *r_data = NULL;
    unsigned char *d = NULL, *p;
    int r, l;
	unsigned char resp[maxresp];

    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, ISO_GENERAL_AUTHENTICATE,
            0, 0);
    apdu.cla = ISO_COMMAND_CHAINING;

    c_data = NPA_GEN_AUTH_PACE_C_new();
    if (!c_data) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    c_data->auth_token = ASN1_OCTET_STRING_new();
    if (!c_data->auth_token
            || !M_ASN1_OCTET_STRING_set(
                c_data->auth_token, in, in_len)) {
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    r = i2d_NPA_GEN_AUTH_PACE_C(c_data, &d);
    if (r < 0) {
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    apdu.data = (const u8 *) d;
    apdu.datalen = r;
    apdu.lc = r;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Perform Key Agreement) command data", apdu.data, apdu.datalen);

    apdu.resplen = sizeof resp;
    apdu.resp = resp;
    if (oldnpactx)
        r = sm_transmit_apdu(oldnpactx, card, &apdu);
    else
        r = sc_transmit_apdu(card, &apdu);
    if (r < 0)
        goto err;

    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    if (r < 0)
        goto err;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Perform Key Agreement) response data", apdu.resp, apdu.resplen);

    if (!d2i_NPA_GEN_AUTH_PACE_R(&r_data,
                (const unsigned char **) &apdu.resp, apdu.resplen)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse general authenticate response data.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    if (r_data->enc_nonce
            || r_data->mapping_data
            || r_data->eph_pub_key
            || !r_data->auth_token) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Response data of general authenticate for "
                "step 4 should (only) contain the authentication token.");
        r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
        goto err;
    }
    p = r_data->auth_token->data;
    l = r_data->auth_token->length;
    if (r_data->cur_car) {
        bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "Most recent Certificate Authority Reference",
                r_data->cur_car->data, r_data->cur_car->length);
        *recent_car = malloc(r_data->cur_car->length);
        if (!*recent_car) {
            r = SC_ERROR_OUT_OF_MEMORY;
            goto err;
        }
        /* Flawfinder: ignore */
        memcpy(*recent_car, r_data->cur_car->data, r_data->cur_car->length);
        *recent_car_len = r_data->cur_car->length;
    } else
        *recent_car_len = 0;
    if (r_data->prev_car) {
        bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "Previous Certificate Authority Reference",
                r_data->prev_car->data, r_data->prev_car->length);
        *prev_car = malloc(r_data->prev_car->length);
        if (!*prev_car) {
            r = SC_ERROR_OUT_OF_MEMORY;
            goto err;
        }
        /* Flawfinder: ignore */
        memcpy(*prev_car, r_data->prev_car->data, r_data->prev_car->length);
        *prev_car_len = r_data->prev_car->length;
    } else
        *prev_car_len = 0;

    *auth_token_out = malloc(l);
    if (!*auth_token_out) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    /* Flawfinder: ignore */
    memcpy(*auth_token_out, p, l);
    *auth_token_out_len = l;

err:
    if (c_data)
        NPA_GEN_AUTH_PACE_C_free(c_data);
    free(d);
    if (r_data)
        NPA_GEN_AUTH_PACE_R_free(r_data);

    return r;
}

int
npa_reset_retry_counter(struct sm_ctx *ctx, sc_card_t *card,
        enum s_type pin_id, int ask_for_secret,
        const char *new, size_t new_len)
{
    sc_apdu_t apdu;
    char *p = NULL;
    int r;

    if (ask_for_secret && (!new || !new_len)) {
        p = malloc(MAX_PIN_LEN+1);
        if (!p) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Not enough memory for new PIN.\n");
            return SC_ERROR_OUT_OF_MEMORY;
        }
        if (0 > EVP_read_pw_string_min(p,
                    MIN_PIN_LEN, MAX_PIN_LEN+1,
                    "Please enter your new PIN: ", 0)) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not read new PIN.\n");
            free(p);
            return SC_ERROR_INTERNAL;
        }
        new_len = strlen(p);
        if (new_len > MAX_PIN_LEN)
            return SC_ERROR_INVALID_PIN_LENGTH;
        new = p;
    }

    memset(&apdu, 0, sizeof apdu);
    apdu.ins = 0x2C;
    apdu.p2 = pin_id;
    apdu.data = (u8 *) new;
    apdu.datalen = new_len;
    apdu.lc = apdu.datalen;

    if (new_len) {
        apdu.p1 = 0x02;
        apdu.cse = SC_APDU_CASE_3_SHORT;
    } else {
        apdu.p1 = 0x03;
        apdu.cse = SC_APDU_CASE_1;
    }

    r = sm_transmit_apdu(ctx, card, &apdu);

    if (p) {
        OPENSSL_cleanse(p, new_len);
        free(p);
    }

    return r;
}

static PACE_SEC *
get_psec(sc_card_t *card, const char *pin, size_t length_pin, enum s_type pin_id)
{
    char *p = NULL;
    PACE_SEC *r;
    int sc_result;
    /* Flawfinder: ignore */
    char buf[MAX_MRZ_LEN > 32 ? MAX_MRZ_LEN : 32];

    if (!length_pin || !pin) {
        if (0 > snprintf(buf, sizeof buf, "Please enter your %s: ",
                    npa_secret_name(pin_id))) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not create password prompt.\n");
            return NULL;
        }
        p = malloc(MAX_MRZ_LEN+1);
        if (!p) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Not enough memory for %s.\n",
                    npa_secret_name(pin_id));
            return NULL;
        }
        if (0 > EVP_read_pw_string_min(p, 0, MAX_MRZ_LEN, buf, 0)) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not read %s.\n",
                    npa_secret_name(pin_id));
            return NULL;
        }
        length_pin = strlen(p);
        if (length_pin > MAX_MRZ_LEN) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "MRZ too long");
            return NULL;
        }
        pin = p;
    }

    r = PACE_SEC_new(pin, length_pin, pin_id);

    if (p) {
        OPENSSL_cleanse(p, length_pin);
        free(p);
    }

    return r;
}

int EstablishPACEChannel(struct sm_ctx *oldnpactx, sc_card_t *card,
        struct establish_pace_channel_input pace_input,
        struct establish_pace_channel_output *pace_output,
        struct sm_ctx *sctx, enum eac_tr_version tr_version)
{
    u8 *p = NULL;
	EAC_CTX *eac_ctx = NULL;
	BUF_MEM *enc_nonce = NULL, *mdata = NULL, *mdata_opp = NULL,
			*token_opp = NULL, *token = NULL, *pub = NULL, *pub_opp = NULL,
			*comp_pub = NULL, *comp_pub_opp = NULL;
    PACE_SEC *sec = NULL;
    CVC_CHAT *chat = NULL;
    BIO *bio_stdout = NULL;
	CVC_CERTIFICATE_DESCRIPTION *desc = NULL;
    int r;
    const unsigned char *pp;

    if (!card || !pace_output || !sctx)
        return SC_ERROR_INVALID_ARGUMENTS;

    /* show description in advance to give the user more time to read it...
     * This behaviour differs from TR-03119 v1.1 p. 44. */
    if (pace_input.certificate_description_length &&
            pace_input.certificate_description) {

        pp = pace_input.certificate_description;
		if (!d2i_CVC_CERTIFICATE_DESCRIPTION(&desc,
                    &pp, pace_input.certificate_description_length)) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse certificate description.");
            ssl_error(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}

        if (!bio_stdout)
            bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
        if (!bio_stdout) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not create output buffer.");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }

        printf("Certificate Description\n");
		switch(certificate_description_print(bio_stdout, desc, 8)) {
            case 0:
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not print certificate description.");
                ssl_error(card->ctx);
                r = SC_ERROR_INTERNAL;
                goto err;
                break;
            case 1:
                /* text format */
                break;
            case 2:
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Certificate description in "
                        "HTML format can not (yet) be handled.");
                r = SC_ERROR_NOT_SUPPORTED;
                goto err;
                break;
            case 3:
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Certificate description in "
                        "PDF format can not (yet) be handled.");
                r = SC_ERROR_NOT_SUPPORTED;
                goto err;
                break;
            default:
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Certificate description in "
                        "unknown format can not be handled.");
                r = SC_ERROR_NOT_SUPPORTED;
                goto err;
                break;
        }
    }

    /* show chat in advance to give the user more time to read it...
     * This behaviour differs from TR-03119 v1.1 p. 44. */
    if (pace_input.chat_length && pace_input.chat) {

        if (!bio_stdout)
            bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
        if (!bio_stdout) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not create output buffer.");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }

        pp = pace_input.chat;
        if (!d2i_CVC_CHAT(&chat, &pp, pace_input.chat_length)) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse card holder authorization template (CHAT).");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }

        printf("Card holder authorization template (CHAT)\n");
        if (!cvc_chat_print(bio_stdout, chat, 8)) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not print card holder authorization template (CHAT).");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }
    }

    if (card->reader->capabilities & SC_READER_CAP_PACE_GENERIC) {
        r = sc_perform_pace(card, &pace_input, pace_output);
    } else {
        if (!pace_output->ef_cardaccess_length || !pace_output->ef_cardaccess) {
            r = get_ef_card_access(oldnpactx, card, &pace_output->ef_cardaccess,
                    &pace_output->ef_cardaccess_length);
            if (r < 0) {
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not get EF.CardAccess.");
                goto err;
            }
        }
        bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "EF.CardAccess", pace_output->ef_cardaccess,
                pace_output->ef_cardaccess_length);

        eac_ctx = EAC_CTX_new();
        if (!eac_ctx
                || !EAC_CTX_init_ef_cardaccess(pace_output->ef_cardaccess,
                    pace_output->ef_cardaccess_length, eac_ctx)) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse EF.CardAccess.");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }

        eac_ctx->tr_version = tr_version;

        r = npa_mse_set_at_pace(oldnpactx, card, eac_ctx->pace_ctx->protocol,
                pace_input.pin_id, chat, &pace_output->mse_set_at_sw1,
                &pace_output->mse_set_at_sw2);
        if (r < 0) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not select protocol proberties "
                    "(MSE: Set AT failed).");
            goto err;
        }

        enc_nonce = BUF_MEM_new();
        if (!enc_nonce) {
            ssl_error(card->ctx);
            r = SC_ERROR_OUT_OF_MEMORY;
            goto err;
        }
        r = npa_gen_auth_1_encrypted_nonce(oldnpactx, card, (u8 **) &enc_nonce->data,
                &enc_nonce->length);
        if (r < 0) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not get encrypted nonce from card "
                    "(General Authenticate step 1 failed).");
            goto err;
        }
        bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "Encrypted nonce from MRTD", (u8 *)enc_nonce->data, enc_nonce->length);
        enc_nonce->max = enc_nonce->length;

        sec = get_psec(card, (char *) pace_input.pin, pace_input.pin_length,
                pace_input.pin_id);
        if (!sec) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not encode PACE secret.");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }

        if (!PACE_STEP2_dec_nonce(eac_ctx, sec, enc_nonce)) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not decrypt MRTD's nonce.");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }

        mdata_opp = BUF_MEM_new();
        mdata = PACE_STEP3A_generate_mapping_data(eac_ctx);
        if (!mdata || !mdata_opp) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not generate mapping data.");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }
        r = npa_gen_auth_2_map_nonce(oldnpactx, card, (u8 *) mdata->data, mdata->length,
                (u8 **) &mdata_opp->data, &mdata_opp->length);
        if (r < 0) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not exchange mapping data with card "
                    "(General Authenticate step 2 failed).");
            goto err;
        }
        mdata_opp->max = mdata_opp->length;
        bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "Mapping data from MRTD", (u8 *) mdata_opp->data, mdata_opp->length);

        if (!PACE_STEP3A_map_generator(eac_ctx, mdata_opp)) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not map generator.");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }

        pub = PACE_STEP3B_generate_ephemeral_key(eac_ctx);
        pub_opp = BUF_MEM_new();
        if (!pub || !pub_opp) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not generate ephemeral domain parameter or "
                    "ephemeral key pair.");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }
        r = npa_gen_auth_3_perform_key_agreement(oldnpactx, card, (u8 *) pub->data, pub->length,
                (u8 **) &pub_opp->data, &pub_opp->length);
        if (r < 0) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not exchange ephemeral public key with card "
                    "(General Authenticate step 3 failed).");
            goto err;
        }
        pub_opp->max = pub_opp->length;
        bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "Ephemeral public key from MRTD", (u8 *) pub_opp->data, pub_opp->length);


        if (!PACE_STEP3B_compute_shared_secret(eac_ctx, pub_opp)
                || !PACE_STEP3C_derive_keys(eac_ctx)) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not compute ephemeral shared secret or "
                    "derive keys for encryption and authentication.");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }
        token = PACE_STEP3D_compute_authentication_token(eac_ctx, pub_opp);
        token_opp = BUF_MEM_new();
        if (!token || !token_opp) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not compute authentication token.");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }
        r = npa_gen_auth_4_mutual_authentication(oldnpactx, card, (u8 *) token->data, token->length,
                (u8 **) &token_opp->data, &token_opp->length,
                &pace_output->recent_car, &pace_output->recent_car_length,
                &pace_output->previous_car, &pace_output->previous_car_length);

        if (r < 0) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not exchange authentication token with card "
                    "(General Authenticate step 4 failed).");
            goto err;
        }
        token_opp->max = token_opp->length;

        if (!PACE_STEP3D_verify_authentication_token(eac_ctx, token_opp)) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not verify authentication token.");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }

        /* Initialize secure channel */
        if (!EAC_CTX_set_encryption_ctx(eac_ctx, EAC_ID_PACE)) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not initialize encryption.");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }

        /* Identifier for ICC and PCD */
        comp_pub = EAC_Comp(eac_ctx, EAC_ID_PACE, pub);
        comp_pub_opp = EAC_Comp(eac_ctx, EAC_ID_PACE, pub_opp);
        if (!comp_pub || !comp_pub_opp) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not compress public keys for identification.");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }
        p = realloc(pace_output->id_icc, comp_pub_opp->length);
        if (!p) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Not enough memory for ID ICC.\n");
            r = SC_ERROR_OUT_OF_MEMORY;
            goto err;
        }
        pace_output->id_icc = p;
        pace_output->id_icc_length = comp_pub_opp->length;
        /* Flawfinder: ignore */
        memcpy(pace_output->id_icc, comp_pub_opp->data, comp_pub_opp->length);
        bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "ID ICC", pace_output->id_icc,
                pace_output->id_icc_length);
        p = realloc(pace_output->id_pcd, comp_pub->length);
        if (!p) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Not enough memory for ID PCD.\n");
            r = SC_ERROR_OUT_OF_MEMORY;
            goto err;
        }
        pace_output->id_pcd = p;
        pace_output->id_pcd_length = comp_pub->length;
        /* Flawfinder: ignore */
        memcpy(pace_output->id_pcd, comp_pub->data, comp_pub->length);
        bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "ID PCD", pace_output->id_pcd,
                pace_output->id_pcd_length);

        sctx->priv_data = npa_sm_ctx_create(eac_ctx,
                pace_input.certificate_description,
                pace_input.certificate_description_length,
                pace_output->id_icc,
                pace_output->id_icc_length);
        if (!sctx->priv_data) {
            r = SC_ERROR_OUT_OF_MEMORY;
            goto err;
        }
        sctx->authenticate = npa_sm_authenticate;
        sctx->encrypt = npa_sm_encrypt;
        sctx->decrypt = npa_sm_decrypt;
        sctx->verify_authentication = npa_sm_verify_authentication;
        sctx->pre_transmit = npa_sm_pre_transmit;
        sctx->post_transmit = npa_sm_post_transmit;
        sctx->finish = npa_sm_finish;
        sctx->clear_free = npa_sm_clear_free;
        sctx->padding_indicator = SM_ISO_PADDING;
        sctx->block_length = EVP_CIPHER_block_size(eac_ctx->key_ctx->cipher);
        sctx->active = 1;
    }

err:
    if (enc_nonce)
        BUF_MEM_free(enc_nonce);
    if (mdata)
        BUF_MEM_free(mdata);
    if (mdata_opp)
        BUF_MEM_free(mdata_opp);
    if (token_opp)
        BUF_MEM_free(token_opp);
    if (token)
        BUF_MEM_free(token);
    if (pub)
        BUF_MEM_free(pub);
    if (pub_opp)
        BUF_MEM_free(pub_opp);
    if (comp_pub_opp)
        BUF_MEM_free(comp_pub_opp);
    if (comp_pub)
        BUF_MEM_free(comp_pub);
    if (sec)
        PACE_SEC_clear_free(sec);
    if (bio_stdout)
        BIO_free_all(bio_stdout);
    if (desc)
        CVC_CERTIFICATE_DESCRIPTION_free(desc);

    if (r < 0) {
        if (eac_ctx)
            EAC_CTX_clear_free(eac_ctx);
        if (sctx->priv_data)
            npa_sm_clear_free(sctx->priv_data);
    }

    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

static int npa_mse_set_dst_ta(struct sm_ctx *npactx, sc_card_t *card,
        const unsigned char *car, size_t car_len)
{
    return npa_mse(npactx, card, 0x81, 0, car, car_len, NULL, 0, NULL, 0,
            NULL, NULL, NULL);
}

static int npa_mse_set_at_ta(struct sm_ctx *npactx, sc_card_t *card,
        const unsigned char *chr, size_t chr_len,
        const unsigned char *auxiliary_data, size_t auxiliary_data_len)
{
    return npa_mse(npactx, card, 0xa1, 0, chr, chr_len, NULL, 0,
            auxiliary_data, auxiliary_data_len, NULL, NULL, NULL);
}

static int npa_get_challenge(struct sm_ctx *npactx, sc_card_t *card,
        unsigned char *challenge, size_t len)
{
    sc_apdu_t apdu;
    int r, class, tag;
    long int length;

    memset(&apdu, 0, sizeof apdu);

    if (!card) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }

    apdu.ins = 0x84;
    apdu.cse = SC_APDU_CASE_2_SHORT;
    apdu.resplen = len;
    apdu.resp = challenge;

    if (npactx)
        r = sm_transmit_apdu(npactx, card, &apdu);
    else
        r = sc_transmit_apdu(card, &apdu);
    if (r < 0)
        goto err;

    r = sc_check_sw(card, apdu.sw1, apdu.sw2);

err:
    return r;
}

static int npa_verify(struct sm_ctx *npactx, sc_card_t *card,
        const unsigned char *cert, size_t cert_len)
{
    sc_apdu_t apdu;
    int r, class, tag;
    long int length;

    memset(&apdu, 0, sizeof apdu);

    if (!card) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }

    apdu.ins = 0x2A;
    apdu.p1 = 0x00;
    apdu.p2 = 0xbe;
    apdu.cse = SC_APDU_CASE_4_EXT;

    apdu.data = cert;
    if (0x80 & ASN1_get_object(&apdu.data, &length, &tag,
                &class, cert_len)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Error decoding Certificate");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    apdu.datalen = length;
    apdu.lc = length;

    if (npactx)
        r = sm_transmit_apdu(npactx, card, &apdu);
    else
        r = sc_transmit_apdu(card, &apdu);
    if (r < 0)
        goto err;

    r = sc_check_sw(card, apdu.sw1, apdu.sw2);

err:
    return r;
}

static int npa_external_authenticate(struct sm_ctx *npactx, sc_card_t *card,
        const unsigned char *signature, size_t signature_len)
{
    int r;
    sc_apdu_t apdu;
    memset(&apdu, 0, sizeof apdu);

    if (!card) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }

    apdu.ins = 0x82;
    apdu.cse = SC_APDU_CASE_4_SHORT;

    apdu.data = signature;
    apdu.datalen = signature_len;
    apdu.lc = signature_len;

    if (npactx)
        r = sm_transmit_apdu(npactx, card, &apdu);
    else
        r = sc_transmit_apdu(card, &apdu);
    if (r < 0)
        goto err;

    r = sc_check_sw(card, apdu.sw1, apdu.sw2);

err:
    return r;
}

int perform_terminal_authentication(struct sm_ctx *ctx, sc_card_t *card,
        const unsigned char **certs, const size_t *certs_lens,
        const unsigned char *privkey, size_t privkey_len,
        const unsigned char *auxiliary_data, size_t auxiliary_data_len)
{
    int r;
    const unsigned char *cert = NULL;
    size_t cert_len = 0;
    CVC_CERT *cvc_cert = NULL;
    BUF_MEM *my_ta_comp_eph_pubkey = NULL, *nonce = NULL, *signature = NULL;

    if (!card || !ctx->priv_data || !certs_lens || !certs) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }
    struct npa_sm_ctx *eacsmctx = ctx->priv_data;

    eacsmctx->flags = 0;


    while (*certs && *certs_lens) {
        cert = *certs;
        cert_len = *certs_lens;
        if (!CVC_d2i_CVC_CERT(&cvc_cert, &cert, cert_len) || !cvc_cert
                || !cvc_cert->body || !cvc_cert->body->certificate_authority_reference
                || !cvc_cert->body->certificate_holder_reference) {
            ssl_error(card->ctx);
            r = SC_ERROR_INVALID_DATA;
            goto err;
        }
        cert = *certs;

        r = npa_mse_set_dst_ta(ctx, card,
                cvc_cert->body->certificate_authority_reference->data,
                cvc_cert->body->certificate_authority_reference->length);
        if (r < 0) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not select protocol proberties "
                    "(MSE: Set AT failed).");
            goto err;
        }

        r = npa_verify(ctx, card, cert, cert_len);
        if (r < 0)
            goto err;

        certs++;
        certs_lens++;
    }


    if (!EAC_CTX_init_ta(eacsmctx->ctx, privkey, privkey_len, cert, cert_len,
                NULL, 0)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not initialize TA.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    my_ta_comp_eph_pubkey = TA_STEP3_generate_ephemeral_key(eacsmctx->ctx);
    if (!my_ta_comp_eph_pubkey) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not generate CA ephemeral key.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }


    r = npa_mse_set_at_ta(ctx, card,
            cvc_cert->body->certificate_holder_reference->data,
            cvc_cert->body->certificate_holder_reference->length,
            auxiliary_data, auxiliary_data_len);
    if (r < 0) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not select protocol proberties "
                "(MSE: Set AT failed).");
        goto err;
    }

    nonce = BUF_MEM_create(8);
    if (!nonce) {
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    r = npa_get_challenge(ctx, card, nonce->data, nonce->length);
    if (r < 0) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not get nonce for TA.");
        goto err;
    }
    if (!TA_STEP4_set_nonce(eacsmctx->ctx, nonce)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not set nonce for TA.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    eacsmctx->auxiliary_data = BUF_MEM_create_init(auxiliary_data,
            auxiliary_data_len);
    signature = TA_STEP5_sign(eacsmctx->ctx, my_ta_comp_eph_pubkey,
            eacsmctx->id_icc, eacsmctx->auxiliary_data);
    if (!signature) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not generate signature.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    r = npa_external_authenticate(ctx, card, signature->data, signature->length);

err:
    if (cvc_cert)
        CVC_CERT_free(cvc_cert);
    if (my_ta_comp_eph_pubkey)
        BUF_MEM_free(my_ta_comp_eph_pubkey);
    if (nonce)
        BUF_MEM_free(nonce);
    if (signature)
        BUF_MEM_free(signature);

    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

static int npa_mse_set_at_ca(struct sm_ctx *npactx, sc_card_t *card,
        const unsigned char *key_ref, size_t key_ref_len)
{
    return npa_mse(npactx, card, 0x41, 0, NULL, 0, key_ref, key_ref_len, NULL,
            0, NULL, NULL, NULL);
}

static int npa_gen_auth_ca(struct sm_ctx *npactx, sc_card_t *card,
        const BUF_MEM *eph_pub_key, BUF_MEM **nonce, BUF_MEM **token)
{
    sc_apdu_t apdu;
    NPA_GEN_AUTH_CA_C *c_data = NULL;
    NPA_GEN_AUTH_CA_R *r_data = NULL;
    unsigned char *d = NULL;
    int r;
	unsigned char resp[maxresp];

    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, ISO_GENERAL_AUTHENTICATE,
            0, 0);
    apdu.cla = ISO_COMMAND_CHAINING;

    c_data = NPA_GEN_AUTH_CA_C_new();
    if (!c_data) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    c_data->eph_pub_key = ASN1_OCTET_STRING_new();
    if (!c_data->eph_pub_key
            || !M_ASN1_OCTET_STRING_set( c_data->eph_pub_key,
                eph_pub_key->data, eph_pub_key->length)) {
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    r = i2d_NPA_GEN_AUTH_CA_C(c_data, &d);
    if (r < 0) {
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    apdu.data = (const u8 *) d;
    apdu.datalen = r;
    apdu.lc = r;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Perform Key Agreement) command data", apdu.data, apdu.datalen);

    apdu.resplen = sizeof resp;
    apdu.resp = resp;
    if (npactx)
        r = sm_transmit_apdu(npactx, card, &apdu);
    else
        r = sc_transmit_apdu(card, &apdu);
    if (r < 0)
        goto err;

    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    if (r < 0)
        goto err;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Perform Key Agreement) response data", apdu.resp, apdu.resplen);

    if (!d2i_NPA_GEN_AUTH_CA_R(&r_data,
                (const unsigned char **) &apdu.resp, apdu.resplen)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse general authenticate response data.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    if (!r_data->nonce || !r_data->auth_token) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Response data of general authenticate for CA"
                "should contain the nonce and the authentication token.");
        r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
        goto err;
    }

    if (*nonce)
        BUF_MEM_free(*nonce);
    *nonce = BUF_MEM_create_init(r_data->nonce->data,
            r_data->nonce->length);
    if (*token)
        BUF_MEM_free(*token);
    *token = BUF_MEM_create_init(r_data->auth_token->data,
            r_data->auth_token->length);
    if (!*nonce || !*token) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }

err:
    if (c_data)
        NPA_GEN_AUTH_CA_C_free(c_data);
    if (r_data)
        NPA_GEN_AUTH_CA_R_free(r_data);
    free(d);

    return r;
}

int get_ef_card_security(struct sm_ctx *npactx, sc_card_t *card,
        u8 **ef_security, size_t *length_ef_security)
{
    return get_ef(npactx, card, SFID_EF_CARDSECURITY, ef_security, length_ef_security);
}

int perform_chip_authentication(struct sm_ctx *ctx, sc_card_t *card)
{
    int r;
    BUF_MEM *picc_pubkey = NULL, *nonce = NULL, *token = NULL, *eph_pub_key = NULL;
    unsigned char *ef_cardsecurity = NULL;
    size_t ef_cardsecurity_len;

    if (!card || !ctx->priv_data) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }
    struct npa_sm_ctx *eacsmctx = ctx->priv_data;

    eacsmctx->flags = 0;


    /* Passive Authentication */
    r = get_ef_card_security(ctx, card, &ef_cardsecurity, &ef_cardsecurity_len);
    if (r < 0) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not get EF.CardSecurity.");
        goto err;
    }
    /* FIXME patch OpenPACE to do verification of EF.CardSecurity and
     * to call EAC_CTX_init_ca */
    picc_pubkey = CA_get_pubkey(ef_cardsecurity, ef_cardsecurity_len);
    if (!picc_pubkey) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not verify EF.CardSecurity.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    
    if (!CA_STEP4_compute_shared_secret(eacsmctx->ctx, picc_pubkey)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not compute shared secret.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }


    unsigned char key_ref = 1;
    r = npa_mse_set_at_ca(ctx, card, &key_ref, sizeof key_ref);
    if (r < 0) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not select protocol proberties "
                "(MSE: Set AT failed).");
        goto err;
    }


    eph_pub_key = CA_STEP2_get_eph_pubkey(eacsmctx->ctx);
    if (!eph_pub_key) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not derive keys.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    r = npa_gen_auth_ca(ctx, card, eph_pub_key, &nonce, &token);


    if (r < 0 || !CA_STEP6_derive_keys(eacsmctx->ctx, nonce, token)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not derive keys.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }


    /* Initialize secure channel */
    if (!EAC_CTX_set_encryption_ctx(eacsmctx->ctx, EAC_ID_CA)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not initialize encryption.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

err:
    free(ef_cardsecurity);
    if (picc_pubkey)
        BUF_MEM_free(picc_pubkey);
    if (nonce)
        BUF_MEM_free(nonce);
    if (token)
        BUF_MEM_free(token);
    if (eph_pub_key)
        BUF_MEM_free(eph_pub_key);

    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

static const char *MRZ_name = "MRZ";
static const char *PIN_name = "PIN";
static const char *PUK_name = "PUK";
static const char *CAN_name = "CAN";
static const char *UNDEF_name = "UNDEF";
const char *npa_secret_name(enum s_type pin_id) {
    switch (pin_id) {
        case PACE_MRZ:
            return MRZ_name;
        case PACE_PUK:
            return PUK_name;
        case PACE_PIN:
            return PIN_name;
        case PACE_CAN:
            return CAN_name;
        default:
            return UNDEF_name;
    }
}

int
increment_ssc(struct npa_sm_ctx *eacsmctx)
{
    if (!eacsmctx)
        return SC_ERROR_INVALID_ARGUMENTS;

    BN_add_word(eacsmctx->ssc, 1);

    return SC_SUCCESS;
}

int
decrement_ssc(struct npa_sm_ctx *eacsmctx)
{
    if (!eacsmctx)
        return SC_ERROR_INVALID_ARGUMENTS;

    BN_sub_word(eacsmctx->ssc, 1);

    return SC_SUCCESS;
}

int
reset_ssc(struct npa_sm_ctx *eacsmctx)
{
    if (!eacsmctx)
        return SC_ERROR_INVALID_ARGUMENTS;

    BN_zero(eacsmctx->ssc);

    return SC_SUCCESS;
}

static int
npa_sm_encrypt(sc_card_t *card, const struct sm_ctx *ctx,
        const u8 *data, size_t datalen, u8 **enc)
{
    BUF_MEM *encbuf = NULL, *databuf = NULL;
    u8 *p = NULL;
    int r;

    if (!card || !ctx || !enc || !ctx->priv_data) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }
    struct npa_sm_ctx *eacsmctx = ctx->priv_data;

    databuf = BUF_MEM_create_init(data, datalen);
    encbuf = EAC_encrypt(eacsmctx->ctx, eacsmctx->ssc, databuf);
    if (!databuf || !encbuf) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not encrypt data.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    p = realloc(*enc, encbuf->length);
    if (!p) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    *enc = p;
    /* Flawfinder: ignore */
    memcpy(*enc, encbuf->data, encbuf->length);
    r = encbuf->length;

err:
    if (databuf) {
        OPENSSL_cleanse(databuf->data, databuf->max);
        BUF_MEM_free(databuf);
    }
    if (encbuf)
        BUF_MEM_free(encbuf);

    return r;
}

static int
npa_sm_decrypt(sc_card_t *card, const struct sm_ctx *ctx,
        const u8 *enc, size_t enclen, u8 **data)
{
    BUF_MEM *encbuf = NULL, *databuf = NULL;
    u8 *p = NULL;
    int r;

    if (!card || !ctx || !enc || !ctx->priv_data || !data) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }
    struct npa_sm_ctx *eacsmctx = ctx->priv_data;

    encbuf = BUF_MEM_create_init(enc, enclen);
    databuf = EAC_decrypt(eacsmctx->ctx, eacsmctx->ssc, encbuf);
    if (!encbuf || !databuf) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not decrypt data.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    p = realloc(*data, databuf->length);
    if (!p) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    *data = p;
    /* Flawfinder: ignore */
    memcpy(*data, databuf->data, databuf->length);
    r = databuf->length;

err:
    if (databuf) {
        OPENSSL_cleanse(databuf->data, databuf->max);
        BUF_MEM_free(databuf);
    }
    if (encbuf)
        BUF_MEM_free(encbuf);

    return r;
}

static int
npa_sm_authenticate(sc_card_t *card, const struct sm_ctx *ctx,
        const u8 *data, size_t datalen, u8 **macdata)
{
    BUF_MEM *inbuf = NULL, *macbuf = NULL;
    u8 *p = NULL, *ssc = NULL;
    int r;

    if (!card || !ctx || !ctx->priv_data || !macdata) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }
    struct npa_sm_ctx *eacsmctx = ctx->priv_data;

    inbuf = BUF_MEM_create_init(data, datalen);
    if (!inbuf) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }

	macbuf = EAC_authenticate(eacsmctx->ctx, eacsmctx->ssc, inbuf);
    if (!macbuf) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                "Could not compute message authentication code (MAC).");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    p = realloc(*macdata, macbuf->length);
    if (!p) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    *macdata = p;
    /* Flawfinder: ignore */
    memcpy(*macdata, macbuf->data, macbuf->length);
    r = macbuf->length;

err:
    if (inbuf)
        BUF_MEM_free(inbuf);
    if (macbuf)
        BUF_MEM_free(macbuf);
    free(ssc);

    return r;
}

static int
npa_sm_verify_authentication(sc_card_t *card, const struct sm_ctx *ctx,
        const u8 *mac, size_t maclen,
        const u8 *macdata, size_t macdatalen)
{
    int r;
    char *p;
    BUF_MEM *inbuf = NULL, *my_mac = NULL;

    if (!card || !ctx || !ctx->priv_data) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }
    struct npa_sm_ctx *eacsmctx = ctx->priv_data;

    inbuf = BUF_MEM_create_init(macdata, macdatalen);
    if (!inbuf) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }

	my_mac = EAC_authenticate(eacsmctx->ctx, eacsmctx->ssc, inbuf); 
    if (!my_mac) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                "Could not compute message authentication code (MAC) for verification.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    if (my_mac->length != maclen ||
            memcmp(my_mac->data, mac, maclen) != 0) {
        r = SC_ERROR_OBJECT_NOT_VALID;
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                "Authentication data not verified");
        goto err;
    }

    sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Authentication data verified");

    r = SC_SUCCESS;

err:
    if (inbuf)
        BUF_MEM_free(inbuf);
    if (my_mac)
        BUF_MEM_free(my_mac);

    return r;
}

static int
add_tag(unsigned char **asn1new, int constructed, int tag,
        int xclass, const unsigned char *data, size_t len)
{
    unsigned char *p;
    int newlen;

    if (!asn1new || !data)
        return -1;

    newlen = ASN1_object_size(constructed, len, tag);
    if (newlen < 0)
        return newlen;

    p = OPENSSL_realloc(*asn1new, newlen);
    if (!p)
        return -1;
    *asn1new = p;

    ASN1_put_object(&p, constructed, len, tag, xclass);
    memcpy(p, data, len);

    return newlen;
}
static int
npa_sm_pre_transmit(sc_card_t *card, const struct sm_ctx *ctx,
        sc_apdu_t *apdu)
{
    int r;
    CVC_CERT *cvc_cert = NULL;
    unsigned char *cert = NULL;
    int len,  tag, class;
    long int llen;
    BUF_MEM *signature = NULL;
    unsigned char *sequence = NULL, *templates = NULL;
    NPA_MSE_C *msesetat = NULL;
    const unsigned char *p;

    if (!card)
       return SC_ERROR_INVALID_ARGUMENTS;
    if(!ctx || !apdu || !ctx->priv_data) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }
    struct npa_sm_ctx *eacsmctx = ctx->priv_data;

    if (eacsmctx->flags & NPA_FLAG_DISABLE_CHECKS) {
        if (apdu->ins == 0x2a && apdu->p1 == 0x00 && apdu->p2 == 0xbe) {
            /* PSO:Verify Certificate
             * check certificate description to match given certificate */

            len = add_tag(&cert, 1, 0x21, V_ASN1_APPLICATION, apdu->data, apdu->datalen);
            p = cert;
            if (len < 0 || !CVC_d2i_CVC_CERT(&cvc_cert, &p, len)
                    || !cvc_cert || !cvc_cert->body) {
                r = SC_ERROR_INVALID_DATA;
                goto err;
            }

            switch (CVC_get_role(cvc_cert->body->chat)) {
                case CVC_CVCA:
                    sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Processing CVCA certificate");
                    break;

                case CVC_DV:
                case CVC_DocVer:
                    sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Processing DV certificate");
                    break;

                case CVC_Terminal:
                    sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Processing Terminal certificate");

                    if (!eacsmctx->certificate_description) {
                        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                                "Certificate Description missing");
                        r = SC_ERROR_INVALID_DATA;
                        goto err;
                    }

                    switch (CVC_check_description(cvc_cert,
                                (unsigned char *) eacsmctx->certificate_description->data,
                                eacsmctx->certificate_description->length)) {
                        case 1:
                            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                                    "Certificate Description matches Certificate");
                            break;
                        case 0:
                            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                                    "Certificate Description doesn't match Certificate");
                            r = SC_ERROR_INVALID_DATA;
                            goto err;
                            break;
                        default:
                            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                                    "Error verifying Certificate Description");
                            ssl_error(card->ctx);
                            r = SC_ERROR_INTERNAL;
                            goto err;
                            break;
                    }
                    break;

                default:
                    sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Unknown type of certificate");
                    r = SC_ERROR_INVALID_DATA;
                    goto err;
                    break;
            }

            if (!TA_STEP2_import_certificate(eacsmctx->ctx, cert, len)) {
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                        "Error importing certificate");
                ssl_error(card->ctx);
                r = SC_ERROR_INTERNAL;
                goto err;
            }

        } else if (apdu->ins == ISO_MSE && apdu->p2 == 0xa4) {
            /* MSE:Set AT */

            len = add_tag(&sequence, 1, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL, apdu->data, apdu->datalen);
            p = sequence;
            if (len < 0 || !d2i_NPA_MSE_C(&msesetat, &p, len)) {
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse MSE:Set AT.");
                ssl_error(card->ctx);
                r = SC_ERROR_INTERNAL;
                goto err;
            }

            if (apdu->p1 == 0x81) {
                /* CA: fetch auxiliary data and terminal's compressed ephemeral
                 * public key */

                if (msesetat->auxiliary_data) {
                    sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Saving terminal's auxiliary data");
                    if (eacsmctx->auxiliary_data)
                        BUF_MEM_free(eacsmctx->auxiliary_data);
                    eacsmctx->auxiliary_data = BUF_MEM_new();
                    if (!eacsmctx->auxiliary_data) {
                        r = SC_ERROR_OUT_OF_MEMORY;
                        goto err;
                    }
                    /* Note that we can not define CVC_DISCRETIONARY_DATA_TEMPLATES as
                     * item template with the correct tag.  Due to limitations of
                     * OpenSSL it is not possible to *encode* an optional item template
                     * (such as APDU_DISCRETIONARY_DATA_TEMPLATES) in an other item
                     * template (such as NPA_MSE_C). So what we have to do here
                     * is manually adding the correct tag to the saved
                     * CVC_DISCRETIONARY_DATA_TEMPLATES.
                     * See also openssl/crypto/asn1/tasn_dec.c:183
                     */
                    len = i2d_CVC_DISCRETIONARY_DATA_TEMPLATES(msesetat->auxiliary_data, &templates);
                    p = templates;
                    if (len < 0 ||
                            (0x80 & ASN1_get_object(&p, &llen, &tag, &class, len))) {
                        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Error encoding auxiliary data.");
                        ssl_error(card->ctx);
                        r = SC_ERROR_INTERNAL;
                        goto err;
                    }
                    eacsmctx->auxiliary_data->length = add_tag(
                            (unsigned char **) &eacsmctx->auxiliary_data->data, 1,
                            7, V_ASN1_APPLICATION, p, llen);
                    if ((int) eacsmctx->auxiliary_data->length < 0) {
                        r = SC_ERROR_OUT_OF_MEMORY;
                        goto err;
                    }
                    eacsmctx->auxiliary_data->max = eacsmctx->auxiliary_data->length;
                }
                if (msesetat->eph_pub_key) {
                    sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Saving terminal's compressed ephemeral public key");
                    if (eacsmctx->eph_pub_key)
                        BUF_MEM_free(eacsmctx->eph_pub_key);
                    eacsmctx->eph_pub_key =
                        BUF_MEM_create_init(msesetat->eph_pub_key->data,
                                msesetat->eph_pub_key->length);
                    if (!eacsmctx->eph_pub_key) {
                        r = SC_ERROR_OUT_OF_MEMORY;
                        goto err;
                    }
                }
            } else if (apdu->p1 == 0x41) {
                /* TA: Set CAR */

                if (msesetat->key_reference1 && msesetat->key_reference1->data &&
                        msesetat->key_reference1->length) {
                    if (!EAC_CTX_init_ta(eacsmctx->ctx, NULL, 0, NULL, 0,
                                msesetat->key_reference1->data,
                                msesetat->key_reference1->length)) {
                        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not initialize TA.\n");
                        ssl_error(card->ctx);
                        r = SC_ERROR_INTERNAL;
                        goto err;
                    }
                }
            }
        } else if (apdu->ins == 0x82 && apdu->p1 == 0x00 && apdu->p2 == 0x00) {
            /* External Authenticate
             * check terminal's signature */

            signature = BUF_MEM_create_init(apdu->data, apdu->datalen);
            if (!signature) {
                r = SC_ERROR_OUT_OF_MEMORY;
                goto err;
            }
            switch (TA_STEP6_verify(eacsmctx->ctx, eacsmctx->eph_pub_key,
                        eacsmctx->id_icc, eacsmctx->auxiliary_data, signature)) {
                case 1:
                    sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                            "Verified Terminal's signature");
                    break;
                case 0:
                    sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                            "Terminal's signature not verified");
                    r = SC_ERROR_INVALID_DATA;
                    goto err;
                    break;
                default:
                    sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                            "Error verifying terminal's signature");
                    ssl_error(card->ctx);
                    r = SC_ERROR_INTERNAL;
                    goto err;
                    break;
            }
        }
    }

    r = increment_ssc(ctx->priv_data);

err:
    if (cvc_cert)
        CVC_CERT_free(cvc_cert);
    if (signature)
        BUF_MEM_free(signature);
    if (cert)
        OPENSSL_free(cert);
    free(sequence);
    if (templates)
        OPENSSL_free(templates);

    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

static int
npa_sm_post_transmit(sc_card_t *card, const struct sm_ctx *ctx,
        sc_apdu_t *sm_apdu)
{
    SC_FUNC_RETURN(card->ctx,  SC_LOG_DEBUG_NORMAL,
            increment_ssc(ctx->priv_data));
}

static int
npa_sm_finish(sc_card_t *card, const struct sm_ctx *ctx,
        sc_apdu_t *apdu)
{
    if (!card)
       return SC_ERROR_INVALID_ARGUMENTS;
    if(!ctx || !ctx->priv_data || !apdu)
        SC_FUNC_RETURN(card->ctx,  SC_LOG_DEBUG_NORMAL,
                SC_ERROR_INVALID_ARGUMENTS);
    struct npa_sm_ctx *eacsmctx = ctx->priv_data;

    if (eacsmctx->flags & NPA_FLAG_DISABLE_CHECKS) {
        if (apdu->sw1 == 0x90 && apdu->sw2 == 0x00) {
            if (apdu->ins == 0x84 && apdu->p1 == 0x00 && apdu->p2 == 0x00
                    && apdu->le == 8 && apdu->resplen == 8) {
                /* Get Challenge
                 * copy challenge to EAC context */

                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Saving MRTD's nonce to later verify Terminal's signature");

                BUF_MEM *nonce = BUF_MEM_create_init(apdu->resp, apdu->resplen);
                int r = TA_STEP4_set_nonce(eacsmctx->ctx, nonce);
                if (nonce)
                    BUF_MEM_free(nonce);

                if (!r) {
                    ssl_error(card->ctx);
                    SC_FUNC_RETURN(card->ctx,  SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
                }
            }
        }
    }

    SC_FUNC_RETURN(card->ctx,  SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}

static void
npa_sm_clear_free(const struct sm_ctx *ctx)
{
    if (ctx) {
        struct npa_sm_ctx *eacsmctx = ctx->priv_data;
        EAC_CTX_clear_free(eacsmctx->ctx);
        if (eacsmctx->ssc)
            BN_clear_free(eacsmctx->ssc);
        if (eacsmctx->certificate_description)
            BUF_MEM_free(eacsmctx->certificate_description);
        if (eacsmctx->id_icc)
            BUF_MEM_free(eacsmctx->id_icc);
        if (eacsmctx->eph_pub_key)
            BUF_MEM_free(eacsmctx->eph_pub_key);
        if (eacsmctx->auxiliary_data)
            BUF_MEM_free(eacsmctx->auxiliary_data);
        free(eacsmctx);
    }
}
