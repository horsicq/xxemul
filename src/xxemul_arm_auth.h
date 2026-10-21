#ifndef XXEMUL_ARM_AUTH_H
#define XXEMUL_ARM_AUTH_H

/* Interpreted pointer authentication: 48-bit guest virtual addresses and a
 * deterministic 16-bit software signature. This checks key/modifier/address
 * consistency across PAC, AUT, authenticated branches and dyld fixups. It is
 * an ABI execution model, not hardware QARMA or a cryptographic protection.
 * Tagged/52-bit pointers and newer FEAT_PAuth_LR instructions are unsupported.
 * Failed authentication reports ADDRESS_FAULT before changing registers/PC.
 */
#define XXEMUL_ARM_AUTH_ADDRESS_MASK UINT64_C(0x0000ffffffffffff)

static inline uint64_t xxemul_arm_auth_strip(uint64_t pointer)
{
    return pointer & XXEMUL_ARM_AUTH_ADDRESS_MASK;
}

static inline xxemul_status xxemul_arm_auth_sign(const xxemul *emulator, uint64_t pointer,
                                               uint64_t modifier, unsigned key, uint64_t *result)
{
    uint64_t hash;
    if (!emulator || !result || key > 3u) return XXEMUL_STATUS_INVALID_ARGUMENT;
    if (pointer & ~XXEMUL_ARM_AUTH_ADDRESS_MASK) return XXEMUL_STATUS_ADDRESS_FAULT;
    hash = pointer ^ modifier ^ (emulator->region_address * UINT64_C(0x9e3779b97f4a7c15)) ^
           ((uint64_t)(key + 1u) * UINT64_C(0xd6e8feb86659fd93));
    hash = (hash ^ (hash >> 30u)) * UINT64_C(0xbf58476d1ce4e5b9);
    hash = (hash ^ (hash >> 27u)) * UINT64_C(0x94d049bb133111eb);
    hash ^= hash >> 31u;
    /* A nonzero signature ensures a raw pointer cannot authenticate. */
    hash = (hash & UINT64_C(0xffff)) | UINT64_C(0x8000);
    *result = pointer | (hash << 48u);
    return XXEMUL_STATUS_OK;
}

static inline xxemul_status xxemul_arm_auth_check(const xxemul *emulator, uint64_t pointer,
                                                uint64_t modifier, unsigned key, uint64_t *result)
{
    uint64_t expected;
    xxemul_status status;
    if (!result) return XXEMUL_STATUS_INVALID_ARGUMENT;
    status = xxemul_arm_auth_sign(emulator, xxemul_arm_auth_strip(pointer), modifier, key, &expected);
    if (status != XXEMUL_STATUS_OK) return status;
    if (expected != pointer) return XXEMUL_STATUS_ADDRESS_FAULT;
    *result = xxemul_arm_auth_strip(pointer);
    return XXEMUL_STATUS_OK;
}

static inline uint64_t xxemul_arm_auth_modifier(uint64_t slot, uint16_t diversity, int address_diversity)
{
    return address_diversity ? xxemul_arm_auth_strip(slot) | ((uint64_t)diversity << 48u) : (uint64_t)diversity;
}

#endif
