import PySide6.QtWidgets as QtWidgets

from .. import pe_file, elf_file
from .components import table
import logging


class ExportsView(QtWidgets.QWidget):
    NAME = "Exports"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.setLayout(QtWidgets.QVBoxLayout())

        # Exports
        self.exports_table = table.TableView(
            fit_columns=True,
            fit_to_contents=False,
            headers=["Name", "Ordinal", "Address"],
        )
        self.layout().addWidget(self.exports_table)

    def load(self, exe: pe_file.PEFile | elf_file.ELFFile):
        logging.getLogger("exespy").debug(f"Loading headers for {exe.__class__}")
        if isinstance(exe, pe_file.PEFile):
            logging.getLogger("exespy").debug("Loading PE file!")
            self.load_pe(exe)
        elif isinstance(exe, elf_file.ELFFile):
            logging.getLogger("exespy").debug("Loading ELF file!")
            self.load_elf(exe)

    def load_pe(self, pe_obj: pe_file.PEFile):
        # Exports
        exports_list = []

        if hasattr(pe_obj.pe, "DIRECTORY_ENTRY_EXPORT"):
            for symbol in pe_obj.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if symbol.name:
                    name = symbol.name.decode("utf-8").strip("\x00")
                else:
                    name = f"[Ordinal {symbol.ordinal}]"

                exports_list.append((name, symbol.ordinal, hex(symbol.address)))

        self.exports_table.setModel(
            table.TableModel(exports_list, headers=["Name", "Ordinal", "Address"])
        )

    def load_elf(self, elf_obj: elf_file.ELFFile):
        pass
