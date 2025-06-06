import PySide6.QtWidgets as QtWidgets

from .. import pe_file, elf_file
from .components import table
import logging


class LibrariesView(QtWidgets.QWidget):
    NAME = "Libraries"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.setLayout(QtWidgets.QVBoxLayout())

        # Libraries
        self.libraries_table = table.TableView(
            fit_columns=True, fit_to_contents=False, headers=["Name", "Imports"]
        )
        self.layout().addWidget(self.libraries_table)

    def load(self, exe: pe_file.PEFile | elf_file.ELFFile):
        logging.getLogger("exespy").debug(f"Loading headers for {exe.__class__}")
        if isinstance(exe, pe_file.PEFile):
            logging.getLogger("exespy").debug("Loading PE file!")
            self.load_pe(exe)
        elif isinstance(exe, elf_file.ELFFile):
            logging.getLogger("exespy").debug("Loading ELF file!")
            self.load_elf(exe)

    def load_pe(self, pe_obj: pe_file.PEFile):
        # Libraries
        libraries_list = []
        if hasattr(pe_obj.pe, "DIRECTORY_ENTRY_IMPORT"):
            for import_obj in pe_obj.pe.DIRECTORY_ENTRY_IMPORT:
                libraries_list.append(
                    (
                        import_obj.dll.decode("utf-8").strip("\x00"),
                        len(import_obj.imports),
                    )
                )

        self.libraries_table.setModel(
            table.TableModel(libraries_list, headers=["Name", "Imports"])
        )

    def load_elf(self, elf_obj: elf_file.ELFFile):
        pass
