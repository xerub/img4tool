/*
 * img4 tool
 * xerub 2015
 */


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef USE_CORECRYPTO
#include <corecrypto/ccrsa.h>
#include <corecrypto/ccsha1.h>
#else
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#endif
#include <libDER/DER_Decode.h>
#include <libDER/asn1Types.h>
#include <libDER/oids.h>
#include "validate_ca.h"

#define E000000000000000 (ASN1_CONSTRUCTED | ASN1_PRIVATE)

#define IS_EQUAL(a, b) ((a).length == (b).length && !memcmp((a).data, (b).data, (a).length))

#define FOURCC(tag) (unsigned char)((tag) >> 24), (unsigned char)((tag) >> 16), (unsigned char)((tag) >> 8), (unsigned char)(tag)

#define RESERVE_DIGEST_SPACE 20

#define panic(fn, args...) do { fprintf(stderr, fn args); exit(1); } while (0)

typedef enum {
    DictMANP,
    DictOBJP
} DictType;

typedef struct {
    DERItem item;
    DERTag tag;
} DERMonster;

typedef struct {
    DERItem magic;      // "IM4P"
    DERItem type;       // "illb"
    DERItem version;    // "iBoot-2261.3.33"
    DERItem imageData;
    DERItem keybag;
    DERByte full_digest[RESERVE_DIGEST_SPACE];
} TheImg4Payload;

typedef struct {
    DERItem magic;      // "IM4M"
    DERItem version;    // 0
    DERItem theset;     // MANB + MANP
    DERItem sig_blob;   // RSA
    DERItem chain_blob; // cert chain
    DERItem img4_blob;
    DERByte full_digest[RESERVE_DIGEST_SPACE];
    DERByte theset_digest[RESERVE_DIGEST_SPACE];
} TheImg4Manifest;

typedef struct {
    DERItem magic;      // "IM4R"
    DERItem nonce;
} TheImg4RestoreInfo;

typedef struct {
    bool payloadHashed;
    bool manifestHashed;
    DERItem payloadRaw;
    DERItem manifestRaw;
    DERItem manb;
    DERItem manp;
    DERItem objp;
    TheImg4Payload payload;
    TheImg4Manifest manifest;
    TheImg4RestoreInfo restoreInfo;
} TheImg4;

const DERItemSpec DERImg4ItemSpecs[4] = {
    { 0 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "IMG4"
    { 1 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        DER_DEC_SAVE_DER },     // SEQUENCE(payload)
    { 2 * sizeof(DERItem), ASN1_CONSTRUCTED|ASN1_CONTEXT_SPECIFIC | 0,  DER_DEC_OPTIONAL },     // CONS(SEQUENCE(manifest))
    { 3 * sizeof(DERItem), ASN1_CONSTRUCTED|ASN1_CONTEXT_SPECIFIC | 1,  DER_DEC_OPTIONAL }      // CONS(SEQUENCE(restoreInfo))
};

const DERItemSpec DERImg4PayloadItemSpecs[5] = {
    { 0 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "IM4P"
    { 1 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "illb"
    { 2 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "iBoot-2261.3.33"
    { 3 * sizeof(DERItem), ASN1_OCTET_STRING,                           0 },                    // binary data
    { 4 * sizeof(DERItem), ASN1_OCTET_STRING,                           DER_DEC_OPTIONAL }      // keybag
};

const DERItemSpec DERImg4ManifestItemSpecs[5] = {
    { 0 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "IM4M"
    { 1 * sizeof(DERItem), ASN1_INTEGER,                                0 },                    // 0
    { 2 * sizeof(DERItem), ASN1_CONSTR_SET,                             DER_DEC_SAVE_DER },     // SET(things)
    { 3 * sizeof(DERItem), ASN1_OCTET_STRING,                           0 },                    // RSA
    { 4 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 }                     // chain
};

const DERItemSpec DERImg4RestoreInfoItemSpecs[2] = {
    { 0 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "IM4R"
    { 1 * sizeof(DERItem), ASN1_CONSTR_SET,                             0 }                     // SET(nonce)
};

const DERItemSpec DERSignedCertCrlItemSpecs[3] = {
    { 0 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        DER_DEC_SAVE_DER },
    { 1 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 2 * sizeof(DERItem), ASN1_BIT_STRING,                             0 }
};

const DERItemSpec DERTBSCertItemSpecs[10] = {
    { 0 * sizeof(DERItem), ASN1_CONSTRUCTED|ASN1_CONTEXT_SPECIFIC | 0,  DER_DEC_OPTIONAL },
    { 1 * sizeof(DERItem), ASN1_INTEGER,                                0 },
    { 2 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 3 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 4 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 5 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 6 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 7 * sizeof(DERItem), ASN1_CONTEXT_SPECIFIC | 1,                   DER_DEC_OPTIONAL },
    { 8 * sizeof(DERItem), ASN1_CONTEXT_SPECIFIC | 2,                   DER_DEC_OPTIONAL },
    { 9 * sizeof(DERItem), ASN1_CONSTRUCTED|ASN1_CONTEXT_SPECIFIC | 3,  DER_DEC_OPTIONAL }
};

const DERItemSpec DERAttributeTypeAndValueItemSpecs[2] = {
    { 0 * sizeof(DERItem), ASN1_OBJECT_ID,                              0 },
    { 1 * sizeof(DERItem), 0,                                           DER_DEC_ASN_ANY | DER_DEC_SAVE_DER }
};

const DERItemSpec DERExtensionItemSpecs[3] = {
    { 0 * sizeof(DERItem), ASN1_OBJECT_ID,                              0 },
    { 1 * sizeof(DERItem), ASN1_BOOLEAN,                                DER_DEC_OPTIONAL },
    { 2 * sizeof(DERItem), ASN1_OCTET_STRING,                           0 }
};

const DERItemSpec DERAlgorithmIdItemSpecs[2] = {
    { 0 * sizeof(DERItem), ASN1_OBJECT_ID,                              0 },
    { 1 * sizeof(DERItem), 0,                                           DER_DEC_OPTIONAL | DER_DEC_ASN_ANY | DER_DEC_SAVE_DER }
};

const DERItemSpec DERSubjPubKeyInfoItemSpecs[2] = {
    { 0 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 },
    { 1 * sizeof(DERItem), ASN1_BIT_STRING,                             0 }
};

const DERItemSpec DERRSAPubKeyPKCS1ItemSpecs[2] = {
    { 0 * sizeof(DERItem), ASN1_INTEGER,                                0x100 },
    { 1 * sizeof(DERItem), ASN1_INTEGER,                                0x100 }
};

const DERByte _oidAppleImg4ManifestCertSpec[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 6, 1, 0xF };
const DERItem oidAppleImg4ManifestCertSpec = { (DERByte *)_oidAppleImg4ManifestCertSpec, sizeof(_oidAppleImg4ManifestCertSpec) };

const DERItem AppleSecureBootCA = { (DERByte *)"\x13)Apple Secure Boot Certification Authority", 0x2B };

/*****************************************************************************/

int
DERImg4DecodeTagCompare(const DERItem *a1, uint32_t nameTag)
{
    uint32_t var_14;

    if (a1->length < 4) {
        return -1;
    }
    if (a1->length > 4) {
        return 1;
    }

    if (DERParseInteger(a1, &var_14)) {
        return -2;
    }

    if (var_14 < nameTag) {
        return -1;
    }
    if (var_14 > nameTag) {
        return 1;
    }
    return 0;
}

int
DERImg4Decode(const DERItem *a1, DERItem *a2)
{
    int rv;
    DERDecodedInfo var_38;

    if (a1 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }

    rv = DERDecodeItem(a1, &var_38);
    if (rv) {
        return rv;
    }

    if (var_38.tag != ASN1_CONSTR_SEQUENCE) {
        return DR_UnexpectedTag;
    }

    if (a1->data + a1->length != var_38.content.data + var_38.content.length) {
        return DR_BufOverflow;
    }

    rv = DERParseSequenceContent(&var_38.content, 4, DERImg4ItemSpecs, a2, 0);
    if (rv) {
        return rv;
    }

    if (DERImg4DecodeTagCompare(a2, 'IMG4')) {
        return DR_UnexpectedTag;
    }

    return 0;
}

int
DERImg4DecodePayload(const DERItem *a1, TheImg4Payload *a2)
{
    int rv;

    if (a1 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }

    rv = DERParseSequence(a1, 5, DERImg4PayloadItemSpecs, a2, 0);
    if (rv) {
        return rv;
    }

    if (DERImg4DecodeTagCompare(&a2->magic, 'IM4P')) {
        return DR_UnexpectedTag;
    }

    return 0;
}

int
DERImg4DecodeManifest(const DERItem *a1, TheImg4Manifest *a2)
{
    int rv;
    uint32_t var_14;

    if (a1 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }
    if (a1->data == NULL || a1->length == 0) {
        return 0;
    }

    rv = DERParseSequence(a1, 5, DERImg4ManifestItemSpecs, a2, 0);
    if (rv) {
        return rv;
    }

    if (DERImg4DecodeTagCompare(&a2->magic, 'IM4M')) {
        return DR_UnexpectedTag;
    }

    rv = DERParseInteger(&a2->version, &var_14);
    if (rv) {
        return rv;
    }

    if (var_14) {
        return DR_UnexpectedTag;
    }
    return 0;
}

int
DERImg4DecodeRestoreInfo(const DERItem *a1, TheImg4RestoreInfo *a2)
{
    int rv;

    if (a1 == NULL) {
        return 0;
    }
    if (a2 == NULL) {
        return DR_ParamErr;
    }
    if (a1->data == NULL || a1->length == 0) {
        return 0;
    }

    rv = DERParseSequence(a1, 2, DERImg4RestoreInfoItemSpecs, a2, 0);
    if (rv) {
        return rv;
    }

    if (DERImg4DecodeTagCompare(&a2->magic, 'IM4R')) {
        return DR_UnexpectedTag;
    }

    return 0;
}

int
Img4DecodeGetPayload(TheImg4 *img4, DERItem *a2)
{
    if (img4 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }
    if (img4->payload.imageData.data == NULL || img4->payload.imageData.length == 0) {
        return DR_EndOfSequence;
    }
    *a2 = img4->payload.imageData;
    return 0;
}

int
Img4DecodeGetPayloadType(TheImg4 *img4, unsigned int *a2)
{
    if (img4 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }
    if (img4->payload.imageData.data == NULL || img4->payload.imageData.length == 0) {
        return DR_EndOfSequence;
    }
    return DERParseInteger(&img4->payload.type, a2);
}

int
Img4DecodeGetPayloadKeybag(TheImg4 *img4, DERItem *a2)
{
    if (img4 == NULL || a2 == NULL) {
        return DR_ParamErr;
    }
    if (img4->payload.imageData.data == NULL || img4->payload.imageData.length == 0) {
        return DR_EndOfSequence;
    }
    *a2 = img4->payload.keybag;
    return 0;
}

int
Img4DecodeManifestExists(TheImg4 *img4, bool *exists)
{
    if (img4 == NULL || exists == NULL) {
        return DR_ParamErr;
    }
    *exists = (img4->manifestRaw.data != NULL);
    return 0;
}

int
Img4DecodeInit(DERByte *data, DERSize length, TheImg4 *img4)
{
    int rv;
    DERItem var_70[4];
    DERItem var_30;

    if (data == NULL || img4 == NULL) {
        return DR_ParamErr;
    }

    var_30.data = data;
    var_30.length = length;

    memset(var_70, 0, sizeof(var_70));
    memset(img4, 0, sizeof(TheImg4));

    rv = DERImg4Decode(&var_30, var_70);
    if (rv) {
        return rv;
    }
    rv = DERImg4DecodePayload(&var_70[1], &img4->payload);
    if (rv) {
        return rv;
    }
    rv = DERImg4DecodeManifest(&var_70[2], &img4->manifest);
    if (rv) {
        return rv;
    }
    rv = DERImg4DecodeRestoreInfo(&var_70[3], &img4->restoreInfo);
    if (rv) {
        return rv;
    }

    img4->payloadRaw = var_70[1];
    img4->manifestRaw = var_70[2];
    return 0;
}

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef USE_CORECRYPTO
#include <corecrypto/ccaes.h>
#else
#include <openssl/aes.h>
#endif
#define DWORD_BE(data, offset) __builtin_bswap32(*(uint32_t *)((char *)(data) + (offset)))
#include "lzss.c"

#define OUTSET(ptr) do { if (outdup) { free(output); } output = ptr; outdup = 1; } while (0)

static unsigned char *
read_file(const char *filename, off_t off, size_t *size)
{
    int fd;
    size_t rv, sz;
    struct stat st;
    unsigned char *buf;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        return NULL;
    }

    rv = fstat(fd, &st);
    if (rv) {
        close(fd);
        return NULL;
    }

    if (off > st.st_size) {
        off = st.st_size;
    }
    sz = st.st_size - off;

    buf = malloc(sz);
    if (buf == NULL) {
        close(fd);
        return NULL;
    }

    rv = read(fd, buf, sz);
    close(fd);

    if (rv != sz) {
        free(buf);
        return NULL;
    }

    if (size != NULL) {
        *size = sz;
    }
    return buf;
}

static ssize_t
write_file(const char *filename, void *buf, size_t size)
{
    ssize_t rv;
    int fd = creat(filename, 0644);
    if (fd < 0) {
        return -1;
    }
    rv = write(fd, buf, size);
    close(fd);
    return rv;
}

static int
str2hex(int buflen, unsigned char *buf, const char *str)
{
    unsigned char *ptr = buf;
    int seq = -1;
    while (buflen > 0) {
        int nibble = *str++;
        if (nibble >= '0' && nibble <= '9') {
            nibble -= '0';
        } else {
            nibble |= 0x20;
            if (nibble >= 'a' && nibble <= 'f') {
                nibble -= 'a' - 10;
            } else {
                break;
            }
        }
        if (seq >= 0) {
            *buf++ = (seq << 4) | nibble;
            buflen--;
            seq = -1;
        } else {
            seq = nibble;
        }
    }
    return buf - ptr;
}

static TheImg4 *
parse(unsigned char *data, unsigned length)
{
    int rv;
    TheImg4 *img4;

    img4 = malloc(sizeof(TheImg4));
    if (!img4) {
        return NULL;
    }
    memset(img4, 0, sizeof(TheImg4));

    rv = Img4DecodeInit(data, length, img4);
    if (rv) {
        DERItem item;
        item.data = data;
        item.length = length;
        rv = DERImg4DecodePayload(&item, &img4->payload);
    }
    if (rv) {
        free(img4);
        return NULL;
    }

    return img4;
}

int
main(int argc, char **argv)
{
    int rv;
    const char *what;
    const char *filename;
    const char *outname;

    TheImg4 *img4;
    unsigned type;
    unsigned written;
    unsigned char ivkey[16 + 32];
    unsigned char *iv = NULL, *key = NULL;
    unsigned char *output = NULL;
    unsigned outlen = 0;
    int outdup = 0;

    DERItem item;
    unsigned char *data;
    size_t size;

    if (argc < 4) {
        fprintf(stderr, "usage: %s {-image|-extra|-keybag|-ticket} input output [ivkey]\n", argv[0]);
        return 1;
    }

    what = argv[1];
    filename = argv[2];
    outname = argv[3];
    if (argc > 4) {
        rv = str2hex(sizeof(ivkey), ivkey, argv[4]);
        if (rv == sizeof(ivkey)) {
            iv = ivkey;
            key = ivkey + 16;
        }
    }

    data = read_file(filename, 0, &size);
    if (data == NULL) {
        fprintf(stderr, "[e] cannot read '%s'\n", filename);
        return -1;
    }

    img4 = parse(data, size);
    if (!img4) {
        fprintf(stderr, "[e] cannot parse '%s'\n", filename);
        free(data);
        return -1;
    }

    rv = Img4DecodeGetPayloadType(img4, &type);
    if (rv) {
        fprintf(stderr, "[e] cannot identify '%s'\n", filename);
        goto err;
    }
    printf("%c%c%c%c\n", FOURCC(type));

    if (!strncmp(what, "-i", 2) || !strncmp(what, "-e", 2)) {
        int decompress;

        rv = Img4DecodeGetPayload(img4, &item);
        if (rv) {
            fprintf(stderr, "[e] cannot extract payload from '%s'\n", filename);
            goto err;
        }
        output = item.data;
        outlen = item.length;

        if (iv && key) {
            if (outlen & 15) {
                unsigned usize = (outlen + 15) & ~15;
                unsigned char *tmp = calloc(1, usize);
                if (!tmp) {
                    fprintf(stderr, "[e] out of memory %u\n", usize);
                    goto err;
                }
                memcpy(tmp, output, outlen);
                OUTSET(tmp);
            }

            rv = Img4DecodeGetPayloadKeybag(img4, &item);
            if (rv || item.length == 0) {
                fprintf(stderr, "[w] image '%s' has no keybag\n", filename);
            }
#ifdef USE_CORECRYPTO
            cccbc_one_shot(ccaes_cbc_decrypt_mode(), 32, key, iv, (outlen + 15) / 16, output, output);
#else
            AES_KEY decryptKey;
            AES_set_decrypt_key(key, 256, &decryptKey);
            AES_cbc_encrypt(output, output, (outlen + 15) & ~15, &decryptKey, iv, AES_DECRYPT);
#endif
        }

        decompress = (DWORD_BE(output, 0) == 'comp' && DWORD_BE(output, 4) == 'lzss');
        if (decompress && what[1] == 'i') {
            uint32_t csize = DWORD_BE(output, 16);
            uint32_t usize = DWORD_BE(output, 12);
            uint32_t adler = DWORD_BE(output, 8);
            unsigned char *dec = malloc(usize);
            if (outlen > 0x180 + csize) {
                fprintf(stderr, "[i] extra 0x%x bytes after compressed chunk\n", outlen - 0x180 - csize);
            }
            if (!dec) {
                fprintf(stderr, "[e] out of memory %u\n", usize);
                goto err;
            }
            outlen = decompress_lzss(dec, output + 0x180, csize);
            if (adler != lzadler32(dec, outlen)) {
                fprintf(stderr, "[w] adler32 mismatch\n");
            }
            OUTSET(dec);
        } else if (decompress) {
            uint32_t csize = DWORD_BE(output, 16);
            uint32_t usize = outlen - 0x180 - csize;
            if (outlen > 0x180 + csize) {
                unsigned char *dec = malloc(usize);
                if (!dec) {
                    fprintf(stderr, "[e] out of memory %u\n", usize);
                    goto err;
                }
                memcpy(dec, output + 0x180 + csize, usize);
                outlen = usize;
                OUTSET(dec);
            } else {
                OUTSET(NULL);
            }
        } else if (what[1] == 'e') {
            OUTSET(NULL);
        }
        if (!output) {
            fprintf(stderr, "[e] nothing to do\n");
            goto err;
        }
    }
    if (!strncmp(what, "-k", 2)) {
        rv = Img4DecodeGetPayloadKeybag(img4, &item);
        if (rv == 0 && item.length) {
            output = item.data;
            outlen = item.length;
        } else {
            fprintf(stderr, "[e] image '%s' has no keybag\n", filename);
            goto err;
        }
    }
    if (!strncmp(what, "-t", 2)) {
        bool exists = false;
        rv = Img4DecodeManifestExists(img4, &exists);
        if (rv == 0 && exists) {
            output = img4->manifestRaw.data;
            outlen = img4->manifestRaw.length;
        } else {
            fprintf(stderr, "[e] image '%s' has no ticket\n", filename);
            goto err;
        }
    }

    written = write_file(outname, output, outlen);
    if (written != outlen) {
        fprintf(stderr, "[e] cannot write '%s'\n", outname);
        goto err;
    }

    rv = 0;
out:
    if (outdup) {
        free(output);
    }
    free(img4);
    free(data);
    return rv;

err:
    rv = -1;
    goto out;
}
