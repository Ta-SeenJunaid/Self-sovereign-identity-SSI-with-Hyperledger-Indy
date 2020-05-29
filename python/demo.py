import subprocess
import logging
import time
import json
from typing import Optional

from indy import pool, wallet, did, ledger, crypto

from indy.error import IndyError, ErrorCode

from src.utils import run_coroutine, get_pool_genesis_txn_path, PROTOCOL_VERSION

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


async def run():
    bash_command = "bash refresh.sh"
    process = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    logger.info("Code Started -> started")

    pool_name = 'pool1'
    logger.info("Open Pool Ledger: {}".format(pool_name))
    pool_genesis_txn_path = get_pool_genesis_txn_path(pool_name)
    pool_config = json.dumps({"genesis_txn": str(pool_genesis_txn_path)})

    #Set protocol version 2
    await pool.set_protocol_version(PROTOCOL_VERSION)

    try:
        await pool.create_pool_ledger_config(pool_name, pool_config)
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass

    pool_handle = await pool.open_pool_ledger(pool_name, None)

    logger.info("==========================================================================")
    logger.info("== Getting Trust Anchor credentials for CUET(Chittagong University of Engineering & Technology),"
                " BJIT Group, City Bank and Government ==")
    logger.info("**************************************************************************")

    logger.info("\"Bd Steward\" -> Create wallet")
    steward_wallet_config = json.dumps({"id" : "bd_steward_wallet"})
    steward_wallet_credentials = json.dumps({"key": "steward_wallet_key"})
    try:
        await wallet.create_wallet(steward_wallet_config, steward_wallet_credentials)
    except IndyError as ex:
        if ex.error_code == ErrorCode.WalletAlreadyExistsError:
            pass

    steward_wallet = await  wallet.open_wallet(steward_wallet_config, steward_wallet_credentials)

    logger.info("\"Bd Steward\" -> Create and store in Wallet DID from seed")
    steward_did_info = {'seed': '000000000000000000000000Steward1'}
    (steward_did, steward_key) = await did.create_and_store_my_did(steward_wallet, json.dumps(steward_did_info))

    logger.info("==========================================================================")
    logger.info("== Getting Trust Anchor credentials - Government Onboarding ==")
    logger.info("**************************************************************************")

    government_wallet_config = json.dumps({"id": "government_wallet"})
    government_wallet_credentials = json.dumps({"key": "government_wallet_key"})
    government_wallet, steward_government_key, government_steward_did, government_steward_key, _ \
        = await onboarding(pool_handle, "Bd Steward", steward_wallet, steward_did, "Government", None,
                           government_wallet_config, government_wallet_credentials)


    logger.info("==========================================================================")
    logger.info("== Getting Trust Anchor credentials - Government getting Verinym ==")
    logger.info("**************************************************************************")

    government_did = await get_verinym(pool_handle, "Bd Steward", steward_wallet, steward_did,
                                       steward_government_key, "Government", government_wallet, government_steward_did,
                                       government_steward_key, 'TRUST_ANCHOR')

    logger.info("==========================================================================")
    logger.info("== Getting Trust Anchor credentials - CUET Onboarding ==")
    logger.info("**************************************************************************")

    cuet_wallet_config = json.dumps({"id": "cuet_wallet"})
    cuet_wallet_credentials = json.dumps({"key": "cuet_wallet_key"})
    cuet_wallet, steward_cuet_key, cuet_steward_did, cuet_steward_key, _ = \
        await onboarding(pool_handle, "Bd Steward", steward_wallet, steward_did, "Cuet", None, cuet_wallet_config,
                         cuet_wallet_credentials)

    logger.info("==========================================================================")
    logger.info("== Getting Trust Anchor credentials - CUET getting Verinym ==")
    logger.info("**************************************************************************")


    cuet_did = await get_verinym(pool_handle, "Bd Steward", steward_wallet, steward_did, steward_cuet_key,
                                  "Cuet", cuet_wallet, cuet_steward_did, cuet_steward_key, 'TRUST_ANCHOR')

    logger.info("==========================================================================")
    logger.info("== Getting Trust Anchor credentials - BJIT Onboarding ==")
    logger.info("**************************************************************************")

    bjit_wallet_config = json.dumps({"id": "bjit_wallet"})
    bjit_wallet_credentials = json.dumps({"key": "bjit_wallet_key"})
    bjit_wallet, steward_bjit_key, bjit_steward_did, bjit_steward_key, _ = \
        await onboarding(pool_handle, "Bd Steward", steward_wallet, steward_did, "Bjit", None, bjit_wallet_config,
                         bjit_wallet_credentials)

    logger.info("==========================================================================")
    logger.info("== Getting Trust Anchor credentials - BJIT getting Verinym ==")
    logger.info("**************************************************************************")

    bjit_did = await get_verinym(pool_handle, "Bd Steward", steward_wallet, steward_did, steward_bjit_key,
                                 "Bjit", bjit_wallet, bjit_steward_did, bjit_steward_key, 'TRUST_ANCHOR')

    logger.info("==========================================================================")


async def onboarding(pool_handle, _from, from_wallet, from_did, to, to_wallet: Optional[str], to_wallet_config: str,
                     to_wallet_credentials: str):
    logger.info("\"{}\" -> Create and store in Wallet \"{} {}\" DID".format(_from, _from, to))
    (from_to_did, from_to_key) = await did.create_and_store_my_did(from_wallet, "{}")

    logger.info("\"{}\" -> Send Nym to Ledger for \"{} {}\" DID".format(_from, _from, to))
    await send_nym(pool_handle, from_wallet, from_did, from_to_did, from_to_key, None)

    logger.info("\"{}\" -> Send connection request to {} with \"{} {}\" DID and nonce".format(_from, to, _from, to))
    connection_request = {
        'did': from_to_did,
        'nonce': 123456789
    }

    if not to_wallet:
        logger.info("\"{}\" -> Create wallet".format(to))
        try:
            await wallet.create_wallet(to_wallet_config, to_wallet_credentials)
        except IndyError as ex:
            if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
                pass
        to_wallet = await wallet.open_wallet(to_wallet_config, to_wallet_credentials)

    logger.info("\"{}\" -> Create and store in Wallet \"{} {}\" DID".format(to, to, _from))
    (to_from_did, to_from_key) = await did.create_and_store_my_did(to_wallet, "{}")

    logger.info("\"{}\" -> Get key for did from \"{}\" connection request".format(to, _from))
    from_to_verkey = await did.key_for_did(pool_handle, to_wallet, connection_request['did'])

    logger.info("\"{}\" -> Anoncrypt connection response for \"{}\" with \"{} {}\" DID, verkey and nonce"
                .format(to, _from, to, _from))
    connection_response = json.dumps({
        'did': to_from_did,
        'verkey': to_from_key,
        'nonce': connection_request['nonce']
    })
    anoncrypted_connection_response = await crypto.anon_crypt(from_to_verkey, connection_response.encode('utf-8'))

    logger.info("\"{}\" -> Send anoncrypted connection response to \"{}\"".format(to, _from))

    logger.info("\"{}\" -> Anondecrypt connection response from \"{}\"".format(_from, to))
    decrypted_connection_response = \
        json.loads((await crypto.anon_decrypt(from_wallet, from_to_key,
                                              anoncrypted_connection_response)).decode("utf-8"))

    logger.info("\"{}\" -> Authenticates \"{}\" by comparision of Nonce".format(_from, to))
    assert connection_request['nonce'] == decrypted_connection_response['nonce']

    logger.info("\"{}\" -> Send Nym to Ledger for \"{} {}\" DID".format(_from, to, _from))
    await send_nym(pool_handle, from_wallet, from_did, to_from_did, to_from_key, None)

    return to_wallet, from_to_key, to_from_did, to_from_key, decrypted_connection_response


async def get_verinym(pool_handle, _from, from_wallet, from_did, from_to_key,
                      to, to_wallet, to_from_did, to_from_key, role):
    logger.info("\"{}\" -> Create and store in Wallet \"{}\" new DID".format(to, to))
    (to_did, to_key) = await did.create_and_store_my_did(to_wallet, "{}")

    logger.info("\"{}\" -> Authcrypt \"{} DID info\" for \"{}\"".format(to, to, _from))
    did_info_json = json.dumps({
        'did': to_did,
        'verkey': to_key
    })
    authcrypted_did_info_json = \
        await crypto.auth_crypt(to_wallet, to_from_key, from_to_key, did_info_json.encode('utf-8'))

    logger.info("\"{}\" -> Send authcrypted \"{} DID info\" to {}".format(to, to, _from))

    logger.info("\"{}\" -> Authdecrypted \"{} DID info\" from {}".format(_from, to, to))
    sender_verkey, authdecrypted_did_info_json, authdecrypted_did_info = \
        await auth_decrypt(from_wallet, from_to_key, authcrypted_did_info_json)

    logger.info("\"{}\" -> Authenticate {} by comparision of Verkeys".format(_from, to, ))
    assert sender_verkey == await did.key_for_did(pool_handle, from_wallet, to_from_did)

    logger.info("\"{}\" -> Send Nym to Ledger for \"{} DID\" with {} Role".format(_from, to, role))
    await send_nym(pool_handle, from_wallet, from_did, authdecrypted_did_info['did'],
                   authdecrypted_did_info['verkey'], role)

    return to_did


async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)


async def auth_decrypt(wallet_handle, key, message):
    from_verkey, decrypted_message_json = await crypto.auth_decrypt(wallet_handle, key, message)
    decrypted_message_json = decrypted_message_json.decode("utf-8")
    decrypted_message = json.loads(decrypted_message_json)
    return from_verkey, decrypted_message_json, decrypted_message

if __name__ == '__main__':
    run_coroutine(run)
    time.sleep(1)