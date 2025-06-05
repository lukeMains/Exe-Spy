import time
import logging
from typing import Union

import PySide6.QtCore as QtCore
import PySide6.QtWidgets as QtWidgets
import PySide6.QtGui as QtGui

import icoextract

from .. import helpers
from .. import pe_file, elf_file
from .components import table


class ChecksumWorker(QtCore.QObject):
    """Calculate the checksum of the PE file asynchronously since it is slow"""

    finished = QtCore.Signal()

    def __init__(self, exe: pe_file.PEFile | elf_file.ELFFile):
        super().__init__()
        self.exe = exe

    def run(self):
        start = time.time()
        self.exe.calculate_checksum()
        logging.getLogger("exespy").debug(
            f" (ASYNC) took {time.time() - start:.4f} seconds"
        )
        self.finished.emit()


class GeneralView(QtWidgets.QScrollArea):
    NAME = "General"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Set up scroll area
        self.setWidgetResizable(True)
        self.scroll_area = QtWidgets.QWidget(self)
        self.setWidget(self.scroll_area)
        self.scroll_area.setLayout(QtWidgets.QFormLayout())

        # File Information group
        ########################
        self.file_group = QtWidgets.QGroupBox("File Information")
        self.file_group.setLayout(QtWidgets.QFormLayout())
        self.scroll_area.layout().addWidget(self.file_group)

        # Name
        self.file_name = QtWidgets.QLabel()
        font = self.file_name.font()
        font.setPointSize(font.pointSize() + 2)
        self.file_name.setFont(font)
        self.file_name.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.file_group.layout().addWidget(self.file_name)

        self.icon = QtWidgets.QLabel()
        self.file_group.layout().addWidget(self.icon)

        # File information group
        self.file_group = table.TableGroup("File Information")
        self.scroll_area.layout().addWidget(self.file_group)

        # Image information group
        self.image_group = table.TableGroup("Image Information")
        self.scroll_area.layout().addWidget(self.image_group)

    def load(self, exe: Union[pe_file.PEFile, elf_file.ELFFile]):
        self.exe = exe

        self.thread = QtCore.QThread()
        self.worker = ChecksumWorker(exe)
        self.worker.moveToThread(self.thread)  # type: ignore
        self.thread.started.connect(self.worker.run)  # type: ignore
        self.worker.finished.connect(self.thread.quit)  # type: ignore
        self.worker.finished.connect(self.worker.deleteLater)  # type: ignore
        self.thread.finished.connect(self.thread.deleteLater)  # type: ignore
        self.thread.start()  # type: ignore
        self.thread.finished.connect(self.show_checksum_result)  # type: ignore

        self.file_name.setText(exe.name)

        if isinstance(exe, pe_file.PEFile):
            try:
                icon = icoextract.IconExtractor(exe.path).get_icon()
                icon.seek(0)
                icon_bytes = icon.read()

                pixmap = QtGui.QPixmap()
                pixmap.loadFromData(icon_bytes)
                pixmap = pixmap.scaled(
                    48, 48, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation
                )
                self.icon.setPixmap(pixmap)
            except icoextract.IconExtractorError:
                pass

        # File Metadata
        c_time = helpers.format_time(exe.stat.st_ctime)
        m_time = helpers.format_time(exe.stat.st_mtime)
        a_time = helpers.format_time(exe.stat.st_atime)
        self.file_group.view.setModel(
            table.TableModel(
                [
                    ("Path", exe.path),
                    ("Created", c_time),
                    ("Modified", m_time),
                    ("Accessed", a_time),
                ]
            )
        )

        # Image Information
        self.model = [
            (
                "Size",
                f"{self.sizeof_fmt(exe.stat.st_size)} ({exe.stat.st_size:,} bytes)",
            ),
            (
                "Timestamp",
                (
                    helpers.format_time(exe.timestamp())
                    if isinstance(exe, pe_file.PEFile)
                    else "-"
                ),
            ),
            ("Type", exe.type()),
            ("Architecture", exe.architecture()),
            (
                "Subsystem",
                exe.subsystem() if isinstance(exe, pe_file.PEFile) else "-",
            ),
            (
                "Image Base",
                (
                    hex(exe.image_base())
                    if isinstance(exe, pe_file.PEFile)
                    else "0x80000000"
                ),
            ),
            ("Entrypoint", hex(exe.entrypoint())),
            (
                "Signature",
                exe.verify_signature() if isinstance(exe, pe_file.PEFile) else "-",
            ),
        ]
        self.image_group.view.setModel(
            table.TableModel(self.model + [("Checksum", "loading...")])
        )

    def show_checksum_result(self):
        """Add the checksum verification result to the table."""
        self.image_group.view.setModel(
            table.TableModel(
                self.model
                + [
                    (
                        "Checksum",
                        (
                            self.exe.verify_checksum()
                            if isinstance(self.exe, pe_file.PEFile)
                            else "-"
                        ),
                    )
                ]
            )
        )
        QtCore.QCoreApplication.processEvents()

    def sizeof_fmt(self, num, suffix="B"):
        for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
            if abs(num) < 1024.0:
                return f"{num:3.1f}{unit}{suffix}"
            num /= 1024.0
        return f"{num:.1f}Yi{suffix}"
