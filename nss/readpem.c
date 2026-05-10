/*
 * NSS does not expose a public API for importing external ML-DSA keys,
 * this file replicates the minimal internal structures needed to decode the
 * DER and create a session key object via PK11_CreateGenericObject.
 */
#include <seccomon.h>
#include <pk11pub.h>
#include <keythi.h>
#include <keyhi.h>
#include <nssb64.h>

#include <secmodti.h>

/* ===== internal key representation ===== */

struct seckeyMLDsaPrivateKeyStr {
    CK_ML_DSA_PARAMETER_SET_TYPE paramSet;
    SECItem seed;
    SECItem privateValue;
};
typedef struct seckeyMLDsaPrivateKeyStr seckeyMLDsaPrivateKey;

struct seckeyRawPrivateKeyStr {
    PLArenaPool *arena;
    KeyType keyType;
    union {
        seckeyMLDsaPrivateKey mldsa;
    } u;
};
typedef struct seckeyRawPrivateKeyStr seckeyRawPrivateKey;


const SEC_ASN1Template seckey_AttributeTemplate[] = {
    { SEC_ASN1_SEQUENCE,
      0, NULL, sizeof(SECKEYAttribute) },
    { SEC_ASN1_OBJECT_ID, offsetof(SECKEYAttribute, attrType) },
    { SEC_ASN1_SET_OF | SEC_ASN1_XTRN, offsetof(SECKEYAttribute, attrValue),
      SEC_ASN1_SUB(SEC_AnyTemplate) },
    { 0 }
};

const SEC_ASN1Template seckey_SetOfAttributeTemplate[] = {
    { SEC_ASN1_SET_OF, 0, seckey_AttributeTemplate },
};

const SEC_ASN1Template seckey_PrivateKeyInfoTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(SECKEYPrivateKeyInfo) },
    { SEC_ASN1_INTEGER, offsetof(SECKEYPrivateKeyInfo, version) },
    { SEC_ASN1_INLINE | SEC_ASN1_XTRN,
      offsetof(SECKEYPrivateKeyInfo, algorithm),
      SEC_ASN1_SUB(SECOID_AlgorithmIDTemplate) },
    { SEC_ASN1_OCTET_STRING, offsetof(SECKEYPrivateKeyInfo, privateKey) },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | 0,
      offsetof(SECKEYPrivateKeyInfo, attributes),
      seckey_SetOfAttributeTemplate },
    { 0 }
};

/* ===== ML-DSA ASN.1 templates ===== */

/* SEQUENCE { seed (OCTET STRING, 32 bytes), privateValue (OCTET STRING) } */
const SEC_ASN1Template seckey_MLDSAPrivateKeyBothExportTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(seckeyRawPrivateKey) },
    { SEC_ASN1_OCTET_STRING, offsetof(seckeyRawPrivateKey, u.mldsa.seed) },
    { SEC_ASN1_OCTET_STRING, offsetof(seckeyRawPrivateKey, u.mldsa.privateValue) },
    { 0 }
};

/* bare OCTET STRING (key only, no seed) */
const SEC_ASN1Template seckey_MLDSAPrivateKeyOnlyExportTemplate[] = {
    { SEC_ASN1_OCTET_STRING, offsetof(seckeyRawPrivateKey, u.mldsa.privateValue) },
    { 0 }
};

/* ===== helpers ===== */

static CK_ML_DSA_PARAMETER_SET_TYPE
get_MLDSAParamSet(SECOidTag algTag)
{
    switch (algTag) {
    case SEC_OID_ML_DSA_44: return CKP_ML_DSA_44;
    case SEC_OID_ML_DSA_65: return CKP_ML_DSA_65;
    case SEC_OID_ML_DSA_87: return CKP_ML_DSA_87;
    default: break;
    }
    return (CK_ULONG)-1UL;
}

static SECKEYPrivateKey *
pk11_MakePrivKey(PK11SlotInfo *slot, KeyType keyType,
                 PRBool isTemp, CK_OBJECT_HANDLE privID, void *wincx)
{
    PLArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (!arena)
        return NULL;

    SECKEYPrivateKey *privKey =
        (SECKEYPrivateKey *)PORT_ArenaZAlloc(arena, sizeof(SECKEYPrivateKey));
    if (!privKey) {
        PORT_FreeArena(arena, PR_FALSE);
        return NULL;
    }

    privKey->arena       = arena;
    privKey->keyType     = keyType;
    privKey->pkcs11Slot  = PK11_ReferenceSlot(slot);
    privKey->pkcs11ID    = privID;
    privKey->pkcs11IsTemp = isTemp;
    privKey->wincx       = wincx;
    return privKey;
}

#define PK11_SETATTRS(x, id, v, l) \
    (x)->type = (id);              \
    (x)->pValue = (v);             \
    (x)->ulValueLen = (l);

/* ===== PKCS#11 import ===== */

static SECStatus
pk11_ImportAndReturnPrivateKey(PK11SlotInfo *slot, seckeyRawPrivateKey *lpk,
                               SECItem *nickname, PRBool isPrivate,
                               unsigned int keyUsage,
                               SECKEYPrivateKey **privk, void *wincx)
{
    CK_BBOOL cktrue  = CK_TRUE;
    CK_BBOOL ckfalse = CK_FALSE;
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_ML_DSA;
    CK_OBJECT_HANDLE objectID;
    CK_ATTRIBUTE theTemplate[10];
    CK_ATTRIBUTE *attrs = theTemplate;
    SECStatus rv = SECFailure;
    PK11GenericObject *genObj = NULL;

    if (lpk->keyType != mldsaKey) {
        PORT_SetError(SEC_ERROR_BAD_KEY);
        return SECFailure;
    }

    if (lpk->u.mldsa.privateValue.len == 0) {
        PORT_SetError(SEC_ERROR_BAD_KEY);
        return SECFailure;
    }

    CK_ML_DSA_PARAMETER_SET_TYPE paramSet = lpk->u.mldsa.paramSet;

    PK11_SETATTRS(attrs, CKA_CLASS,    &keyClass, sizeof(keyClass)); attrs++;
    PK11_SETATTRS(attrs, CKA_KEY_TYPE, &keyType,  sizeof(keyType));  attrs++;
    PK11_SETATTRS(attrs, CKA_TOKEN,    &ckfalse,  sizeof(CK_BBOOL)); attrs++;
    PK11_SETATTRS(attrs, CKA_SENSITIVE,
                  isPrivate ? &cktrue : &ckfalse, sizeof(CK_BBOOL)); attrs++;
    PK11_SETATTRS(attrs, CKA_PRIVATE,
                  isPrivate ? &cktrue : &ckfalse, sizeof(CK_BBOOL)); attrs++;
    PK11_SETATTRS(attrs, CKA_SIGN, &cktrue, sizeof(CK_BBOOL)); attrs++;
    if (nickname) {
        PK11_SETATTRS(attrs, CKA_LABEL, nickname->data, nickname->len); attrs++;
    }
    PK11_SETATTRS(attrs, CKA_PARAMETER_SET, (unsigned char *)&paramSet,
                  sizeof(CK_ML_DSA_PARAMETER_SET_TYPE)); attrs++;
    PK11_SETATTRS(attrs, CKA_VALUE, lpk->u.mldsa.privateValue.data,
                  lpk->u.mldsa.privateValue.len); attrs++;

    PORT_Assert((attrs - theTemplate) <= (int)(sizeof(theTemplate) / sizeof(CK_ATTRIBUTE)));

    genObj = PK11_CreateGenericObject(slot, theTemplate,
                                      attrs - theTemplate, PR_FALSE);
    if (genObj) {
        rv = SECSuccess;
        if (privk) {
            objectID = PK11_GetObjectHandle(PK11_TypeGeneric, genObj, NULL);
            *privk = pk11_MakePrivKey(slot, mldsaKey, PR_TRUE, objectID, wincx);
            if (!*privk)
                rv = SECFailure;
        }
        PK11_DestroyGenericObject(genObj);
    }
    return rv;
}

static SECStatus
pk11_ImportPrivateKeyInfoAndReturnKey(PK11SlotInfo *slot,
                                      SECKEYPrivateKeyInfo *pki,
                                      SECItem *nickname,
                                      PRBool isPrivate, unsigned int keyUsage,
                                      SECKEYPrivateKey **privk, void *wincx)
{
    SECStatus rv = SECFailure;
    seckeyRawPrivateKey *lpk = NULL;
    const SEC_ASN1Template *keyTemplate = NULL;
    PLArenaPool *arena = NULL;
    SECOidTag algTag;

    arena = PORT_NewArena(2048);
    if (!arena)
        return SECFailure;

    lpk = (seckeyRawPrivateKey *)PORT_ArenaZAlloc(arena, sizeof(seckeyRawPrivateKey));
    if (!lpk)
        goto loser;
    lpk->arena = arena;

    algTag = SECOID_GetAlgorithmTag(&pki->algorithm);

    if (algTag == SEC_OID_ML_DSA_44 ||
        algTag == SEC_OID_ML_DSA_65 ||
        algTag == SEC_OID_ML_DSA_87) {
        if (!pki->privateKey.data || pki->privateKey.len == 0) {
            PORT_SetError(SEC_ERROR_BAD_KEY);
            goto loser;
        }
        /* detect key format from first DER byte */
        switch (pki->privateKey.data[0]) {
            case SEC_ASN1_CONSTRUCTED | SEC_ASN1_SEQUENCE:
                keyTemplate = seckey_MLDSAPrivateKeyBothExportTemplate;
                break;
            case SEC_ASN1_OCTET_STRING:
                keyTemplate = seckey_MLDSAPrivateKeyOnlyExportTemplate;
                break;
            default:
                PORT_SetError(SEC_ERROR_BAD_DER);
                goto loser;
        }
        lpk->keyType = mldsaKey;
        lpk->u.mldsa.paramSet = get_MLDSAParamSet(algTag);
    } else {
        PORT_SetError(SEC_ERROR_BAD_KEY);
        goto loser;
    }

    rv = SEC_QuickDERDecodeItem(arena, lpk, keyTemplate, &pki->privateKey);
    if (rv != SECSuccess)
        goto loser;

    rv = pk11_ImportAndReturnPrivateKey(slot, lpk, nickname, isPrivate,
                                        keyUsage, privk, wincx);
loser:
    PORT_FreeArena(arena, PR_TRUE);
    return rv;
}

static SECStatus
pk11_ImportDERPrivateKeyInfoAndReturnKey(PK11SlotInfo *slot, SECItem *derPKI,
                                         SECItem *nickname, PRBool isPrivate,
                                         unsigned int keyUsage,
                                         SECKEYPrivateKey **privk, void *wincx)
{
    PLArenaPool *temparena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    SECStatus rv = SECFailure;

    if (!temparena)
        return rv;

    SECKEYPrivateKeyInfo *pki = PORT_ArenaZNew(temparena, SECKEYPrivateKeyInfo);
    if (!pki) {
        PORT_FreeArena(temparena, PR_FALSE);
        return rv;
    }
    pki->arena = temparena;

    rv = SEC_ASN1DecodeItem(pki->arena, pki, seckey_PrivateKeyInfoTemplate, derPKI);
    if (rv != SECSuccess) {
        PORT_FreeArena(temparena, PR_TRUE);
        return rv;
    }
    if (!pki->privateKey.data || pki->privateKey.len == 0) {
        PORT_FreeArena(temparena, PR_TRUE);
        PORT_SetError(SEC_ERROR_BAD_KEY);
        return SECFailure;
    }

    rv = pk11_ImportPrivateKeyInfoAndReturnKey(slot, pki, nickname, isPrivate,
                                               keyUsage, privk, wincx);
    SECKEY_DestroyPrivateKeyInfo(pki, PR_TRUE);
    return rv;
}

/* ===== raw (non-PEM) import ===== */

/*
 * Import a raw ML-DSA private key directly from a byte buffer.
 * mldsa_level must be 44, 65, or 87.
 */
SECKEYPrivateKey *
import_raw_PrivateKey(const unsigned char *key_buf, size_t key_len, int mldsa_level)
{
    CK_BBOOL cktrue  = CK_TRUE;
    CK_BBOOL ckfalse = CK_FALSE;
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_ML_DSA;
    CK_ML_DSA_PARAMETER_SET_TYPE paramSet;
    CK_ATTRIBUTE theTemplate[10];
    CK_ATTRIBUTE *attrs = theTemplate;
    PK11SlotInfo *slot = NULL;
    PK11GenericObject *genObj = NULL;
    SECKEYPrivateKey *privKey = NULL;

    switch (mldsa_level) {
        case 44: paramSet = CKP_ML_DSA_44; break;
        case 65: paramSet = CKP_ML_DSA_65; break;
        case 87: paramSet = CKP_ML_DSA_87; break;
        default:
            PORT_SetError(SEC_ERROR_BAD_KEY);
            return NULL;
    }

    PK11_SETATTRS(attrs, CKA_CLASS,         &keyClass,  sizeof(keyClass));  attrs++;
    PK11_SETATTRS(attrs, CKA_KEY_TYPE,      &keyType,   sizeof(keyType));   attrs++;
    PK11_SETATTRS(attrs, CKA_TOKEN,         &ckfalse,   sizeof(CK_BBOOL));  attrs++;
    PK11_SETATTRS(attrs, CKA_SENSITIVE,     &ckfalse,   sizeof(CK_BBOOL));  attrs++;
    PK11_SETATTRS(attrs, CKA_PRIVATE,       &ckfalse,   sizeof(CK_BBOOL));  attrs++;
    PK11_SETATTRS(attrs, CKA_SIGN,          &cktrue,    sizeof(CK_BBOOL));  attrs++;
    PK11_SETATTRS(attrs, CKA_PARAMETER_SET, (unsigned char *)&paramSet,
                  sizeof(CK_ML_DSA_PARAMETER_SET_TYPE)); attrs++;
    PK11_SETATTRS(attrs, CKA_VALUE,         (unsigned char *)key_buf, key_len); attrs++;

    slot = PK11_GetInternalSlot();
    if (!slot)
        return NULL;

    genObj = PK11_CreateGenericObject(slot, theTemplate, attrs - theTemplate, PR_FALSE);
    if (!genObj) {
        PK11_FreeSlot(slot);
        return NULL;
    }

    CK_OBJECT_HANDLE objectID = PK11_GetObjectHandle(PK11_TypeGeneric, genObj, NULL);
    privKey = pk11_MakePrivKey(slot, mldsaKey, PR_TRUE, objectID, NULL);

    PK11_DestroyGenericObject(genObj);
    PK11_FreeSlot(slot);
    return privKey;
}

/* ===== PEM import ===== */

#define PRIV_KEY_LABEL "-----BEGIN PRIVATE KEY-----"

static char *
get_DERPKI(FILE *fp)
{
    size_t len, start, end, i, ret;
    char *buf1, *buf2;

    fseek(fp, 0L, SEEK_END);
    len = ftell(fp);
    buf1 = PORT_Alloc(len + 1);
    if (!buf1)
        return NULL;
    rewind(fp);
    ret = fread(buf1, 1, len, fp);
    if (ret != len) {
        PORT_Free(buf1);
        PORT_SetError(SEC_ERROR_INPUT_LEN);
        return NULL;
    }
    buf1[len] = 0;

    for (i = 0; i < len; i++) {
        if (buf1[i] == '-' &&
            PORT_Strncmp(&buf1[i], PRIV_KEY_LABEL,
                         sizeof(PRIV_KEY_LABEL) - 1) == 0) {
            i += sizeof(PRIV_KEY_LABEL) - 1;
            break;
        }
    }
    if (i >= len) {
        PORT_Free(buf1);
        PORT_SetError(SEC_ERROR_INPUT_LEN);
        return NULL;
    }
    start = i;
    for (; i < len; i++) {
        if (buf1[i] == '-')
            break;
    }
    end = i;
    len = end - start;

    buf2 = PORT_Alloc(len + 1);
    PORT_Memcpy(buf2, &buf1[start], len);
    buf2[len] = 0;
    PORT_Free(buf1);
    return buf2;
}

/*
 * Read a PKCS#8 PEM file and return the imported ML-DSA private key.
 */
SECKEYPrivateKey *
read_PrivateKey(FILE *fp)
{
    SECKEYPrivateKey *privkey = NULL;
    char *asciiDerPKI = NULL;
    SECItem derPKI = { siBuffer, NULL, 0 };
    SECItem *item = NULL;
    PK11SlotInfo *slot = NULL;
    SECStatus rv;

    slot = PK11_GetInternalSlot();
    if (!slot)
        goto loser;

    asciiDerPKI = get_DERPKI(fp);
    if (!asciiDerPKI)
        goto loser;

    item = NSSBase64_DecodeBuffer(NULL, &derPKI, asciiDerPKI,
                                  PORT_Strlen(asciiDerPKI));
    if (!item)
        goto loser;

    rv = pk11_ImportDERPrivateKeyInfoAndReturnKey(slot, &derPKI, NULL,
                                                  PR_FALSE, KU_ALL,
                                                  &privkey, NULL);
    if (rv != SECSuccess)
        goto loser;

    PK11_FreeSlot(slot);
    PORT_Free(derPKI.data);
    PORT_Free(asciiDerPKI);
    return privkey;

loser:
    if (slot)       PK11_FreeSlot(slot);
    if (derPKI.data) PORT_Free(derPKI.data);
    if (asciiDerPKI) PORT_Free(asciiDerPKI);
    return NULL;
}
