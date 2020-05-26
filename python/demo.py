import subprocess
import logging
import time
import json

from indy import pool, wallet, did

from indy.error import IndyError, ErrorCode

from src.utils import run_coroutine, get_pool_genesis_txn_path, PROTOCOL_VERSION

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

async def run():
    bashCommand = "bash refresh.sh"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
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




if __name__ == '__main__':
    run_coroutine(run)
    time.sleep(1)