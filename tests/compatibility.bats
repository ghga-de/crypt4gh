#!/usr/bin/env bats

load _common/helpers

# crypt4gh 1.8.6 encrypted testfile.abbbc for Alice, once with Bob's crypt4gh key
# and once with Bob's ssh key. Every later version must still decrypt these files.
FILE_FROM_C4GH_KEY=${HERE}/testfile.abbbc.c4gh
FILE_FROM_SSH_KEY=${HERE}/testfile.abbbc.sshkey.c4gh
BOB_SSH_PUBKEY=${HERE}/bob.sshkey.pub

function setup() {

    # Defining the TMP dir
    TESTFILES=${BATS_TEST_FILENAME}.d
    mkdir -p "$TESTFILES"

}

function teardown() {
    rm -rf ${TESTFILES}
}

@test "Alice decrypts a file from crypt4gh 1.8.6, sent with Bob's crypt4gh key" {

    export C4GH_PASSPHRASE=${ALICE_PASSPHRASE}
    crypt4gh decrypt --sk ${ALICE_SECKEY} --sender_pk ${BOB_PUBKEY} < ${FILE_FROM_C4GH_KEY} > $TESTFILES/received

    run diff ${HERE}/testfile.abbbc $TESTFILES/received
    [ "$status" -eq 0 ]
}

@test "Alice decrypts a file from crypt4gh 1.8.6, sent with Bob's ssh key" {

    # --sender_pk converts Bob's ssh key, which must match the key in the file
    export C4GH_PASSPHRASE=${ALICE_PASSPHRASE}
    crypt4gh decrypt --sk ${ALICE_SECKEY} --sender_pk ${BOB_SSH_PUBKEY} < ${FILE_FROM_SSH_KEY} > $TESTFILES/received

    run diff ${HERE}/testfile.abbbc $TESTFILES/received
    [ "$status" -eq 0 ]
}

@test "Alice rejects a file from crypt4gh 1.8.6 that does not come from the expected sender" {

    export C4GH_PASSPHRASE=${ALICE_PASSPHRASE}
    run crypt4gh decrypt --sk ${ALICE_SECKEY} --sender_pk ${BOB_PUBKEY} < ${FILE_FROM_SSH_KEY}
    [ "$status" -ne 0 ]
}
