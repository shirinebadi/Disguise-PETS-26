#ifndef _CHANNEL_H_
#define _CHANNEL_H_

int generate_session_keys();
int init();
void channel_box(unsigned char* msg, size_t len, unsigned char* buffer, unsigned char* key);
void asymmetric_box(unsigned char* msg, size_t len, unsigned char* buffer, unsigned char* key);
void asymmetric_unbox(unsigned char* encrypted_data, 
                    size_t encrypted_len,
                    unsigned char* decrypted_data);
void channel_unbox(unsigned char* msg_buffer, size_t len, size_t* datalen);
#define MSG_BLOCKSIZE 32
#define BLOCK_UP(len) (len+(MSG_BLOCKSIZE - (len%MSG_BLOCKSIZE)))

typedef struct blake2b_param_ {
    uint8_t digest_length;                   /*  1 */
    uint8_t key_length;                      /*  2 */
    uint8_t fanout;                          /*  3 */
    uint8_t depth;                           /*  4 */
    uint8_t leaf_length[4];                  /*  8 */
    uint8_t node_offset[8];                  /* 16 */
    uint8_t node_depth;                      /* 17 */
    uint8_t inner_length;                    /* 18 */
    uint8_t reserved[14];                    /* 32 */
    uint8_t salt[16];         /* 48 */
    uint8_t personal[16]; /* 64 */
} blake2b_param;

extern unsigned char server_pk[], server_sk[];
extern unsigned char server_spk[], server_ssk[];
extern unsigned char client_pk[];
extern unsigned char client_spk[];
extern unsigned char rx[];
extern unsigned char tx[];
extern unsigned char dev_public_key[];
extern unsigned char Ack[];

#endif /* _CHANNEL_H_ */