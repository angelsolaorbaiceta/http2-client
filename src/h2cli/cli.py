"""A CLI to perform HTTP2 requests, with the purpose of learning how the protocol
works.

Implemented following RFC 7540: https://httpwg.org/specs/rfc7540.html

NOTES:

    - The upgrade mechanism (https://httpwg.org/specs/rfc7540.html#discover-http)
    isn't implemented.
"""

import logging
import sys

from h2cli.connection import HTTP2Connection

_logo = """
▌ ▗ ▗   ▄▖
▛▌▜▘▜▘▛▌▄▌
▌▌▐▖▐▖▙▌▙▖
      ▌
"""

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)

_log = logging.getLogger(__name__)


def main() -> None:
    print(_logo)
    url = input("URL > ")

    if url.startswith("http://"):
        print("The HTTP protocol (h2c) isn't supported. Use 'https://' instead.")
        sys.exit(1)

    if not url.startswith("https://"):
        url = "https://" + url
        logging.info(f"Using {url}")

    connection = HTTP2Connection(url)
    connection.connect()

    input("Close?")
    connection.close()
