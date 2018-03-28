import logging
import sys

log = logging.getLogger('utils')


class LoggerWriter:

    def __init__(self, level):
        self.level = level
        self.linebuf = ''

    def write(self, message):
        for line in message.rstrip().splitlines():
            self.level(line.rstrip())

    def flush(self):
        self.level(sys.stderr)
