#!/usr/bin/env bats

load _common/helpers

# Crafted ssh-ed25519 public keys, which the conversion to curve25519 must reject:
#  - the identity point (y = 1), which has order 1
#  - a y that is not the coordinate of any point on the curve
#  - the base point plus a point of order 2, which lies outside the prime-order subgroup
# ssh-keygen only produces valid keys, so the other tests never reach these checks.
IDENTITY_PUBKEY=${HERE}/invalid.identity.pub
OFF_CURVE_PUBKEY=${HERE}/invalid.off_curve.pub
MIXED_ORDER_PUBKEY=${HERE}/invalid.mixed_order.pub

CONVERSION_ERROR="Can't convert ed25519 public key to curve25519"

@test "Bob does not encrypt to an ssh key holding the identity point" {

    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    run crypt4gh encrypt --sk ${BOB_SECKEY} --recipient_pk ${IDENTITY_PUBKEY} < ${HERE}/testfile.abbbc
    [ "$status" -ne 0 ]
    [[ "$output" == *"${CONVERSION_ERROR}"* ]]
}

@test "Bob does not encrypt to an ssh key holding a point off the curve" {

    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    run crypt4gh encrypt --sk ${BOB_SECKEY} --recipient_pk ${OFF_CURVE_PUBKEY} < ${HERE}/testfile.abbbc
    [ "$status" -ne 0 ]
    [[ "$output" == *"${CONVERSION_ERROR}"* ]]
}

@test "Bob does not encrypt to an ssh key holding a point outside the prime-order subgroup" {

    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    run crypt4gh encrypt --sk ${BOB_SECKEY} --recipient_pk ${MIXED_ORDER_PUBKEY} < ${HERE}/testfile.abbbc
    [ "$status" -ne 0 ]
    [[ "$output" == *"${CONVERSION_ERROR}"* ]]
}
