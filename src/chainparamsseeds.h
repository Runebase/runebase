#ifndef BITCOIN_CHAINPARAMSSEEDS_H
#define BITCOIN_CHAINPARAMSSEEDS_H
/**
 * List of fixed seed nodes for the bitcoin network
 * AUTOGENERATED by contrib/seeds/generate-seeds.py
 *
 * Each line contains a BIP155 serialized (networkID, addr, port) tuple.
 */
static const uint8_t chainparams_seed_main[] = {
    0x01,0x04,0xad,0xf9,0x07,0x3c,0x26,0xdb,
    0x01,0x04,0xcf,0xb4,0xd7,0xb4,0x26,0xdb,
    0x01,0x04,0x90,0x5b,0x73,0x02,0x26,0xdb,
    0x01,0x04,0x90,0x5b,0x69,0x3d,0x26,0xdb,
    0x01,0x04,0x90,0x5b,0x69,0x7c,0x26,0xdb,

};

static const uint8_t chainparams_seed_test[] = {
    0x01,0x04,0xad,0xf9,0x07,0x3c,0x4d,0xeb,
    0x01,0x04,0xcf,0xb4,0xd7,0xb4,0x4d,0xeb,
    0x01,0x04,0x90,0x5b,0x73,0x02,0x4d,0xeb,
    0x01,0x04,0x90,0x5b,0x69,0x3d,0x4d,0xeb,
    0x01,0x04,0x90,0x5b,0x69,0x7c,0x4d,0xeb,
};
#endif // BITCOIN_CHAINPARAMSSEEDS_H
