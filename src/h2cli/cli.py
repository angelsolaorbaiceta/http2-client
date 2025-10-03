"""A CLI to perform HTTP2 requests, with the purpose of learning how the protocol
works.

Implemented following RFC 7540: https://httpwg.org/specs/rfc7540.html

NOTES:

    - The upgrade mechanism (https://httpwg.org/specs/rfc7540.html#discover-http) 
    isn't implemented.
"""

_logo = """
▌ ▗ ▗   ▄▖
▛▌▜▘▜▘▛▌▄▌
▌▌▐▖▐▖▙▌▙▖
      ▌
"""


def main() -> None:
    print(_logo)
