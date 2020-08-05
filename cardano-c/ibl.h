#ifndef CARDANO_IBL_RUST_H
#define CARDANO_IBL_RUST_H

/***********/
/* IBL  */
/***********/

typedef struct cardano_wallet cardano_wallet;
typedef struct cardano_account cardano_account;

char *create_rootkey(const char* mnemonics, const char* password);
char *create_rootkey_from_entropy(const char* mnemonics, const char* password, unsigned int password_size);

cardano_wallet *create_wallet(const char *key);
void delete_wallet(cardano_wallet *wallet);
void delete_account(cardano_account *account);

char *generate_address( const char *key, unsigned int index, int internal,
                        unsigned int from_index, unsigned long num_indices );

char *generate_address_private( const char *key, unsigned int index, int internal,
                        unsigned int from_index, unsigned long num_indices );

char* validate_address(const char *address);
char* validate_private_key(const char* root_key);
char* new_transaction( const char *root_key, const char *utxos, const char *from_addr, const char *to_addrs );
char* transaction_fee( const char *utxos, const char *from_addr, const char *to_addrs);
char* transaction_size( const char *utxos, const char *from_addr, const char *to_addrs);
char* get_txid( const char *root_key, const char *utxos, const char *from_addr, const char *to_addrs );
void decode_raw(const char *raw);
#endif
