from typing import Union
import PySide6.QtWidgets as QtWidgets

from .. import helpers
from .. import pe_file, elf_file
from .components import table


class HeadersView(QtWidgets.QScrollArea):
    NAME = "Headers"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Set up scroll area
        self.setWidgetResizable(True)
        self.scroll_area = QtWidgets.QWidget(self)
        self.setWidget(self.scroll_area)
        self.scroll_area.setLayout(QtWidgets.QFormLayout())

    def load(self, exe: Union[pe_file.PEFile, elf_file.ELFFile]):
        if isinstance(exe, pe_file.PEFile):
            self.load_pe(exe)
        elif isinstance(exe, elf_file.ELFFile):
            self.load_elf(exe)
        else:
            # Should be unreachable
            # TODO: Add logging or popup?
            pass

    def load_pe(self, pe_obj: pe_file.PEFile):

        # Setup Tables
        layout = self.scroll_area.layout()

        # DOS Header
        dos_hdr_cols = ["Name", "Description", "Value"]
        self.dos_header_group = table.TableGroup(
            "DOS Header", fit_columns=True, headers=dos_hdr_cols
        )
        layout.addWidget(self.dos_header_group)

        # COFF File Header
        coff_hdr_cols = ["Name", "Value"]
        self.file_header_group = table.TableGroup(
            "File Header", fit_columns=True, headers=coff_hdr_cols
        )
        layout.addWidget(self.file_header_group)

        # Optional Header
        option_hdr_cols = ["Name", "Value"]
        self.optional_header_group = table.TableGroup(
            "Optional Header", fit_columns=True, headers=option_hdr_cols
        )
        layout.addWidget(self.optional_header_group)

        # DOS Header
        self.dos_header_group.view.setModel(
            table.TableModel(
                [
                    ("e_magic", "Magic number", hex(dos_header.e_magic)),
                    ("e_cblp", "Bytes on last page of file", hex(dos_header.e_cblp)),
                    ("e_cp", "Pages in file", hex(dos_header.e_cp)),
                    ("e_crlc", "Relocations", hex(dos_header.e_crlc)),
                    ("e_cparhdr", "Size of header in paragraphs", hex(dos_header.e_cparhdr)),
                    ("e_minalloc", "Minimum extra paragraphs needed", hex(dos_header.e_minalloc)),
                    ("e_maxalloc", "Maximum extra paragraphs needed", hex(dos_header.e_maxalloc)),
                    ("e_ss", "Initial (relative) SS value", hex(dos_header.e_ss)),
                    ("e_sp", "Initial SP value", hex(dos_header.e_sp)),
                    ("e_csum", "Checksum", hex(dos_header.e_csum)),
                    ("e_ip", "Initial IP value", hex(dos_header.e_ip)),
                    ("e_cs", "Initial (relative) CS value", hex(dos_header.e_cs)),
                    ("e_lfarlc", "File address of relocation table", hex(dos_header.e_lfarlc)),
                    ("e_ovno", "Overlay number", hex(dos_header.e_ovno)),
                    (
                        "e_res",
                        "Reserved words",
                        hex(
                            int.from_bytes(dos_header.e_res, "big"),
                        ),
                    ),
                    ("e_oemid", "OEM identifier (for e_oeminfo)", hex(dos_header.e_oemid)),
                    ("e_oeminfo", "OEM information; e_oemid specific", hex(dos_header.e_oeminfo)),
                    (
                        "e_res2",
                        "Reserved words",
                        hex(
                            int.from_bytes(dos_header.e_res2, "big"),
                        ),
                    ),
                    ("e_lfanew", "File address of new exe header", hex(dos_header.e_lfanew)),
                ],
                headers=dos_hdr_cols,
            )
        )

        # COFF File Header
        file_hdr = pe_obj.pe.FILE_HEADER
        self.file_header_group.view.setModel(
            table.TableModel(
                [
                    (
                        "Machine",
                        f"{hex(file_hdr.Machine)} ({pe_obj.architecture()})",
                    ),
                    ("NumberOfSections", str(file_hdr.NumberOfSections)),
                    (
                        "TimeDateStamp",
                        f"{hex(file_hdr.TimeDateStamp)} ({helpers.format_time(file_hdr.TimeDateStamp)})",
                    ),
                    ("PointerToSymbolTable", hex(file_hdr.PointerToSymbolTable)),
                    ("NumberOfSymbols", str(file_hdr.NumberOfSymbols)),
                    ("SizeOfOptionalHeader", hex(file_hdr.SizeOfOptionalHeader)),
                    (
                        "Characteristics",
                        f"{hex(file_hdr.Characteristics)} ({pe_obj.characteristics_str()})",
                    ),
                ],
                headers=coff_hdr_cols,
            )
        )

        # Optional Header
        base_of_data = []
        try:
            base_of_data.append(("BaseOfData", hex(pe_obj.pe.OPTIONAL_HEADER.BaseOfData)))
        except AttributeError:
            pass

        option_hdr = pe_obj.pe.OPTIONAL_HEADER
        self.optional_header_group.view.setModel(
            table.TableModel(
                [
                    ("Magic", f"{hex(option_hdr.Magic)} ({pe_obj.pe_format()})"),
                    ("MajorLinkerVersion", str(option_hdr.MajorLinkerVersion)),
                    ("MinorLinkerVersion", str(option_hdr.MinorLinkerVersion)),
                    ("SizeOfCode", hex(option_hdr.SizeOfCode)),
                    ("SizeOfInitializedData", hex(option_hdr.SizeOfInitializedData)),
                    ("SizeOfUninitializedData", hex(option_hdr.SizeOfUninitializedData)),
                    ("AddressOfEntryPoint", hex(option_hdr.AddressOfEntryPoint)),
                    ("BaseOfCode", hex(option_hdr.BaseOfCode)),
                ]
                + base_of_data
                + [
                    ("ImageBase", hex(option_hdr.ImageBase)),
                    ("SectionAlignment", hex(option_hdr.SectionAlignment)),
                    ("FileAlignment", hex(option_hdr.FileAlignment)),
                    ("MajorOperatingSystemVersion", str(option_hdr.MajorOperatingSystemVersion)),
                    ("MinorOperatingSystemVersion", str(option_hdr.MinorOperatingSystemVersion)),
                    ("MajorImageVersion", str(option_hdr.MajorImageVersion)),
                    ("MinorImageVersion", str(option_hdr.MinorImageVersion)),
                    ("MajorSubsystemVersion", str(option_hdr.MajorSubsystemVersion)),
                    ("MinorSubsystemVersion", str(option_hdr.MinorSubsystemVersion)),
                    ("Win32VersionValue (reserved)", hex(option_hdr.Reserved1)),
                    ("SizeOfImage", hex(option_hdr.SizeOfImage)),
                    ("SizeOfHeaders", hex(option_hdr.SizeOfHeaders)),
                    ("CheckSum", hex(option_hdr.CheckSum)),
                    ("Subsystem", f"{hex(option_hdr.Subsystem)} ({pe_obj.subsystem()})"),
                    (
                        "DllCharacteristics",
                        f"{hex(option_hdr.DllCharacteristics)}, ({pe_obj.dll_characteristics_str()})",
                    ),
                    ("SizeOfStackReserve", hex(option_hdr.SizeOfStackReserve)),
                    ("SizeOfStackCommit", hex(option_hdr.SizeOfStackCommit)),
                    ("SizeOfHeapReserve", hex(option_hdr.SizeOfHeapReserve)),
                    ("SizeOfHeapCommit", hex(option_hdr.SizeOfHeapCommit)),
                    ("LoaderFlags", hex(option_hdr.LoaderFlags)),
                    ("NumberOfRvaAndSizes", str(option_hdr.NumberOfRvaAndSizes)),
                ],
                headers=option_hdr_cols,
            )
        )

        self.dos_header_group.setFocus()

    def load_elf(self, elf_obj: elf_file.ELFFile):
        """TODO"""

        # Setup Tables
        layout = self.scroll_area.layout()

        # DOS Header
        elf_hdr_cols = ["Name", "Description", "Value"]
        self.elf_file_header_group = table.TableGroup(
            "ELF Header", fit_columns=True, headers=elf_hdr_cols
        )
        layout.addWidget(self.elf_file_header_group)

        # COFF File Header
        program_hdr_cols = ["Name", "Value"]
        self.elf_program_header_group = table.TableGroup(
            "Program Headers", fit_columns=True, headers=program_hdr_cols
        )
        layout.addWidget(self.elf_program_header_group)

        # Optional Header
        elf_section_hdr_cols = ["Name", "Value"]
        self.elf_section_header_group = table.TableGroup(
            "Section Headers", fit_columns=True, headers=elf_section_hdr_cols
        )
        layout.addWidget(self.elf_section_header_group)

        # TODO: Fill out header tables
