#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "ibl.h"

int wallet_test_ibl(void) {
    static char *address;
    static char *rootkey;

    const char* mnemonics = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    const char* password  = "password";

    // rootkey = create_rootkey_from_entropy(mnemonics, password, strlen(password));
    rootkey = create_rootkey(mnemonics, password);
    if (!rootkey) {
        return -1;
    }

    printf("rootkey: %s\n", rootkey);

    address = generate_address(rootkey, 0, 0, 0, 1);

    printf("address generated: %s\n", address);

    printf("address is valid: %s\n", validate_address(address));

    const char *utxos = "[{\"id\": \"5ce31e6ee49813b595ed80c86005c2c8b2dd48c8b9b99e94c741cbe00b4d42e5\", \"index\": 1, \"value\": 102049},{\"id\": \"bec1603219646ac2e4cc79f36cc35dc6d6277bd3735b57912d0691624037c659\", \"index\": 0, \"value\": 100000}]";
    const char *to_addrs = "[{\"addr\": \"Ae2tdPwUPEZJ9dajA1JZR2opisUZzZiXrs61ieZ6RNk91YoeuqatDSpfvhn\",\"value\": 1000}]";

    static char *signed_trx;
    signed_trx = new_transaction(rootkey, utxos, address, to_addrs);
    if (signed_trx) {
        printf("Signed trx success %s\n", signed_trx);
    } else {
        printf("Failed to create new transaction\n");
    }

    const char * fee = transaction_fee(utxos, address, to_addrs);

    printf("Trx Fee: %s\n", fee);
    const char * size = transaction_size(utxos, address, to_addrs);

    printf("Trx size: %s\n", size);

    static char *txid;
    txid = get_txid(rootkey, utxos, address, to_addrs);
    if (txid) {
        printf("txid: %s\n", txid);
    } else {
        printf("Failed to get txid\n");
    }

    decode_raw(signed_trx);

    return 0;
}

int main(int argc, char* argv[]) {
    if (wallet_test_ibl()) exit(35);
    return 0;
}
