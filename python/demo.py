import subprocess
import logging
import time
import json

from indy import pool

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

    logger.info("==============================")


if __name__ == '__main__':
    run_coroutine(run)
    time.sleep(1)