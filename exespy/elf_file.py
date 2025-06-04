import logging
import os
import time

from .readelf import ReadElf

from . import utils


class ELFFile:
    """Base class for representing an ELF file"""

    def __init__(self, path: str):
        """
        Initialize the ELFFile object
        :param path: Path to the ELF file
        """

        self.logger = logging.getLogger("exespy")
        self.logger.info("Loading ELF file: " + path)

        init_start = time.time()

        self.path = path
        self.name = os.path.basename(path)
        self.stat = os.stat(path)

        # Read the ELF file into memory so it can be reused
        self.readelf = ReadElf(open(path, "rb"), None)
        self.elf = self.readelf.elffile

        self.__calculated_checksum = None

        self.sha256 = self.calculate_sha256()

        # Resources

        self.logger.debug(
            f"ELFFile init finished in {time.time() - init_start:.4f} seconds"
        )

    def calculate_checksum(self) -> int:
        """Not relevant to ELF files so returns 0"""
        if self.__calculated_checksum is None:
            self.__calculated_checksum = 0

        return self.__calculated_checksum

    def type(self) -> str:
        """Return the type of the ELF file (executable, shared object, etc.)"""
        if type := self.elf.structs.e_type:
            return type
        else:
            return "Unknown"

    def architecture(self) -> str:
        """Return the architecture of the ELF file"""
        return self.elf.get_machine_arch()

    def is_x86(self) -> bool:
        """TODO"""
        return self.architecture() == "x86" or self.architecture() == "x86_64"

    def is_32bit(self) -> bool:
        """TODO"""
        self.logger.error("FIXME: is_32bit()")
        return False

    def is_64bit(self) -> bool:
        """TODO"""
        self.logger.error("FIXME: is_64bit()")
        return True

    # TODO: Does a build timestamp exist in ELF files, maybe DWARF info?
    def timestamp(self) -> int:
        """TODO"""
        return -1

    def entrypoint(self) -> int:
        """Returns the entrypoint of the ELF file"""
        if addr := self.elf.header["e_entry"]:
            return addr
        else:
            return 0

    def strings(self, min_size=10) -> "set[str]":
        return utils.strings(self.elf.stream.read(), min_size)

    def calculate_sha256(self) -> str:
        return utils.calculate_sha256(self.elf.stream.read())
