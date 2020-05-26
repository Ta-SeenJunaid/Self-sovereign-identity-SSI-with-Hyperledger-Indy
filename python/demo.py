import subprocess
import logging
import time

from src.utils import run_coroutine

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

async def run():
    bashCommand = "bash refresh.sh"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    logger.info("Code Started -> started")

if __name__ == '__main__':
    run_coroutine(run)
    time.sleep(1)