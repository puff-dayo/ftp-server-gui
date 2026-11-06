import os

from PySide6.QtCore import Signal, Qt
from PySide6.QtWidgets import (
    QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QLineEdit,
    QFormLayout, QFileDialog, QTreeWidget, QTreeWidgetItem, QHeaderView,
    QDialog, QDialogButtonBox, QMessageBox, QStyle,
)

from vfs import VirtualMapping, normalize_mappings, normalize_virtual_path


class VirtualMappingDialog(QDialog):
    def __init__(self, parent=None, mapping=None, suggested_virtual="/"):
        super().__init__(parent)
        self.setWindowTitle("Virtual directory mapping")
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.virtual_input = QLineEdit()
        self.virtual_input.setPlaceholderText("/media/photos")
        self.local_input = QLineEdit()
        self.local_input.setPlaceholderText(r"D:\Photos")

        local_row = QHBoxLayout()
        local_row.addWidget(self.local_input, 1)
        browse = QPushButton("Browse")
        browse.clicked.connect(self._browse)
        local_row.addWidget(browse)

        form.addRow("Server path:", self.virtual_input)
        form.addRow("Local folder:", local_row)
        layout.addLayout(form)

        hint = QLabel(
            "Server paths form one virtual tree. Parent folders are created automatically; "
            "only mapped nodes need a local folder."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: palette(mid);")
        layout.addWidget(hint)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._validate_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        if mapping:
            self.virtual_input.setText(mapping.virtual_path)
            self.local_input.setText(mapping.local_path)
        else:
            self.virtual_input.setText(suggested_virtual)

    def _browse(self):
        start = self.local_input.text().strip() or os.path.expanduser("~")
        folder = QFileDialog.getExistingDirectory(self, "Select local folder", start)
        if folder:
            self.local_input.setText(folder)

    def _validate_and_accept(self):
        try:
            virtual = normalize_virtual_path(self.virtual_input.text())
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid server path", str(exc))
            return
        local = os.path.abspath(os.path.expandvars(os.path.expanduser(self.local_input.text().strip())))
        if not local or not os.path.isdir(local):
            QMessageBox.warning(self, "Invalid local folder", "Choose an existing local directory.")
            return
        self.virtual_input.setText(virtual)
        self.local_input.setText(local)
        self.accept()

    def mapping(self):
        return VirtualMapping(normalize_virtual_path(self.virtual_input.text()), os.path.abspath(self.local_input.text()))


class VirtualDirectoryEditor(QWidget):
    mappings_changed = Signal()

    def __init__(self, mappings=None, parent=None):
        super().__init__(parent)
        self._mappings = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(2)
        self.tree.setHeaderLabels(["Server path", "Local folder"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tree.header().setSectionResizeMode(1, QHeaderView.Stretch)
        self.tree.setAlternatingRowColors(True)
        self.tree.itemSelectionChanged.connect(self._update_buttons)
        self.tree.itemDoubleClicked.connect(lambda *_: self._edit_selected())
        layout.addWidget(self.tree, 1)

        actions = QHBoxLayout()
        self.add_button = QPushButton("Add mapping")
        self.edit_button = QPushButton("Edit")
        self.remove_button = QPushButton("Remove")
        self.add_button.clicked.connect(self._add_mapping)
        self.edit_button.clicked.connect(self._edit_selected)
        self.remove_button.clicked.connect(self._remove_selected)
        actions.addWidget(self.add_button)
        actions.addWidget(self.edit_button)
        actions.addWidget(self.remove_button)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.summary = QLabel()
        self.summary.setStyleSheet("color: palette(mid);")
        layout.addWidget(self.summary)
        self.set_mappings(mappings or [])

    def set_mappings(self, mappings):
        self._mappings = list(normalize_mappings(mappings, require_existing=False))
        self._rebuild_tree()

    def mappings(self):
        return list(self._mappings)

    def _rebuild_tree(self):
        self.tree.clear()
        mapping_by_path = {m.virtual_path: m for m in self._mappings}
        root = QTreeWidgetItem(["/", mapping_by_path.get("/").local_path if "/" in mapping_by_path else ""])
        root.setData(0, Qt.UserRole, "/")
        root.setData(1, Qt.UserRole, "/" in mapping_by_path)
        root.setIcon(0, self.style().standardIcon(
            QStyle.StandardPixmap.SP_DriveHDIcon if "/" in mapping_by_path else QStyle.StandardPixmap.SP_DirIcon
        ))
        self.tree.addTopLevelItem(root)

        nodes = {"/": root}
        for mapping in sorted(self._mappings, key=lambda m: (m.virtual_path.count("/"), m.virtual_path.casefold())):
            if mapping.virtual_path == "/":
                continue
            parent_path = "/"
            for segment in mapping.virtual_path.strip("/").split("/"):
                current = parent_path.rstrip("/") + "/" + segment if parent_path != "/" else "/" + segment
                if current not in nodes:
                    item = QTreeWidgetItem([current, ""])
                    item.setData(0, Qt.UserRole, current)
                    item.setData(1, Qt.UserRole, False)
                    item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon))
                    nodes[parent_path].addChild(item)
                    nodes[current] = item
                parent_path = current

            item = nodes[mapping.virtual_path]
            item.setText(1, mapping.local_path)
            item.setData(1, Qt.UserRole, True)
            item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DriveHDIcon))
            item.setToolTip(1, mapping.local_path)

        root.setExpanded(True)
        self.tree.expandAll()
        count = len(self._mappings)
        self.summary.setText(f"{count} mapped folder{'s' if count != 1 else ''}. Changes take effect the next time the server starts.")
        self._update_buttons()

    def _selected_path(self):
        items = self.tree.selectedItems()
        return items[0].data(0, Qt.UserRole) if items else "/"

    def _selected_mapping(self):
        path = self._selected_path()
        return next((m for m in self._mappings if m.virtual_path == path), None)

    def _suggest_child_path(self):
        parent = self._selected_path()
        return "/new-folder" if parent == "/" else parent.rstrip("/") + "/new-folder"

    def _add_mapping(self):
        dialog = VirtualMappingDialog(self, suggested_virtual=self._suggest_child_path())
        if dialog.exec() != QDialog.Accepted:
            return
        new_mapping = dialog.mapping()
        if any(m.virtual_path == new_mapping.virtual_path for m in self._mappings):
            QMessageBox.warning(self, "Duplicate mapping", f"{new_mapping.virtual_path} is already mapped.")
            return
        self._mappings.append(new_mapping)
        self._mappings = normalize_mappings(self._mappings, require_existing=False)
        self._rebuild_tree()
        self.mappings_changed.emit()

    def _edit_selected(self):
        mapping = self._selected_mapping()
        if not mapping:
            return
        dialog = VirtualMappingDialog(self, mapping=mapping)
        if dialog.exec() != QDialog.Accepted:
            return
        replacement = dialog.mapping()
        if any(m.virtual_path == replacement.virtual_path and m.virtual_path != mapping.virtual_path for m in self._mappings):
            QMessageBox.warning(self, "Duplicate mapping", f"{replacement.virtual_path} is already mapped.")
            return
        self._mappings = [replacement if m == mapping else m for m in self._mappings]
        self._mappings = normalize_mappings(self._mappings, require_existing=False)
        self._rebuild_tree()
        self.mappings_changed.emit()

    def _remove_selected(self):
        mapping = self._selected_mapping()
        if not mapping:
            return
        answer = QMessageBox.question(
            self,
            "Remove mapping",
            f"Remove the mapping {mapping.virtual_path}?\n\nNo local files will be deleted.",
        )
        if answer != QMessageBox.Yes:
            return
        self._mappings = [m for m in self._mappings if m != mapping]
        self._rebuild_tree()
        self.mappings_changed.emit()

    def _update_buttons(self):
        has_mapping = self._selected_mapping() is not None
        self.edit_button.setEnabled(has_mapping)
        self.remove_button.setEnabled(has_mapping)


