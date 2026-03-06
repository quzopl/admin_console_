#!/usr/bin/env python3
"""
Pro Admin Tool — NTFS & CD/DVD & Users
Advanced NTFS tab inspired by NTFS Permissions Tools
"""
import sys
import os
import ctypes
import winreg
import subprocess
import win32net
import win32netcon
import win32security
import win32api
import ntsecuritycon as con
import ntsecuritycon
from datetime import datetime
from PySide6 import QtWidgets, QtCore, QtGui

# ---------------------------------------------------------------------------
# STYL
# ---------------------------------------------------------------------------
DARK_STYLE = """
QMainWindow { background: #0d1117; color: #e6e6e6; }
QTabWidget::pane { border: 1px solid #21262d; border-radius: 8px; background: #0d1117; }
QTabBar::tab {
    background: #161b22; color: #8b949e;
    border: 1px solid #21262d; border-bottom: none;
    padding: 8px 20px; margin-right: 2px;
    border-radius: 6px 6px 0 0; font-weight: bold;
}
QTabBar::tab:selected { background: #1f6feb; color: #ffffff; border-color: #1f6feb; }
QTabBar::tab:hover:!selected { background: #21262d; color: #e6e6e6; }
QGroupBox {
    border: 1px solid #21262d; border-radius: 8px;
    margin-top: 12px; padding: 10px 8px 8px 8px;
    font-weight: bold; color: #58a6ff;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; }
QLineEdit, QTextEdit, QTreeView, QTableWidget, QComboBox, QListWidget {
    background: #161b22; border: 1px solid #21262d;
    border-radius: 6px; padding: 5px; color: #e6e6e6;
}
QLineEdit:focus, QComboBox:focus { border-color: #1f6feb; }
QComboBox::drop-down { border: none; }
QComboBox QAbstractItemView {
    background: #161b22; selection-background-color: #1f6feb; color: #e6e6e6;
}
QHeaderView::section {
    background: #161b22; color: #58a6ff;
    border: 1px solid #21262d; padding: 5px; font-weight: bold;
}
QPushButton {
    background: #21262d; border: 1px solid #30363d;
    border-radius: 6px; padding: 7px 14px;
    color: #e6e6e6; font-weight: bold;
}
QPushButton:hover { background: #30363d; border-color: #58a6ff; }
QPushButton:disabled { background: #161b22; color: #484f58; border-color: #21262d; }
QPushButton#btnGreen { background: #238636; border-color: #2ea043; color: #fff; }
QPushButton#btnGreen:hover { background: #2ea043; }
QPushButton#btnRed { background: #8b1a1a; border-color: #b91c1c; color: #fff; }
QPushButton#btnRed:hover { background: #b91c1c; }
QPushButton#btnBlue { background: #1f6feb; border-color: #388bfd; color: #fff; }
QPushButton#btnBlue:hover { background: #388bfd; }
QPushButton#btnOrange { background: #9a6700; border-color: #d29922; color: #fff; }
QPushButton#btnOrange:hover { background: #d29922; }
QPushButton#btnPlus {
    background: #238636; border-color: #2ea043; color: #fff;
    font-size: 18px; padding: 2px 12px;
    border-radius: 6px; min-width: 32px; max-width: 32px;
}
QPushButton#btnPlus:hover { background: #2ea043; }
QCheckBox { color: #c9d1d9; spacing: 6px; }
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1px solid #30363d; border-radius: 3px; background: #161b22;
}
QCheckBox::indicator:checked { background: #1f6feb; border-color: #1f6feb; }
QLabel { color: #c9d1d9; }
QScrollBar:vertical { background: #0d1117; width: 8px; border-radius: 4px; }
QScrollBar::handle:vertical { background: #30363d; border-radius: 4px; min-height: 20px; }
QTableWidget { gridline-color: #21262d; }
QTableWidget::item:selected { background: #1f6feb40; }
QDialog { background: #0d1117; color: #e6e6e6; }
QToolBar { background: #161b22; border-bottom: 1px solid #21262d; spacing: 4px; padding: 4px; }
QToolButton {
    background: #21262d; border: 1px solid #30363d;
    border-radius: 6px; padding: 6px 10px;
    color: #e6e6e6; font-weight: bold; font-size: 11px;
}
QToolButton:hover { background: #30363d; border-color: #58a6ff; }
QToolButton:disabled { background: #161b22; color: #484f58; }
QSplitter::handle { background: #21262d; }
"""

# ---------------------------------------------------------------------------
# HELPER: CHECKBOX WYCENTROWANY
# ---------------------------------------------------------------------------
def centered_cb(checked=False):
    cb = QtWidgets.QCheckBox()
    cb.setChecked(checked)
    w = QtWidgets.QWidget()
    lay = QtWidgets.QHBoxLayout(w)
    lay.addWidget(cb)
    lay.setAlignment(QtCore.Qt.AlignCenter)
    lay.setContentsMargins(0, 0, 0, 0)
    return w, cb


# ---------------------------------------------------------------------------
# HELPER: ACCESS MASK → HUMAN READABLE TEXT
# ---------------------------------------------------------------------------
def mask_to_str(mask: int) -> str:
    if (mask & con.FILE_ALL_ACCESS) == con.FILE_ALL_ACCESS:
        return "Full Control"
    parts = []
    if mask & con.FILE_GENERIC_READ:   parts.append("Odczyt")
    if mask & con.FILE_GENERIC_WRITE:  parts.append("Zapis")
    if mask & con.FILE_GENERIC_EXECUTE: parts.append("Wykonanie")
    if mask & con.DELETE:              parts.append("Usuwanie")
    if mask & con.READ_CONTROL:        parts.append("Read Permissions")
    if mask & con.WRITE_DAC:           parts.append("Change Permissions")
    if mask & con.WRITE_OWNER:         parts.append("Change Owner")
    return ", ".join(parts) if parts else f"Spec. (0x{mask:08X})"



# ---------------------------------------------------------------------------
# HELPER: LOCAL USER LIST
# ---------------------------------------------------------------------------
def get_local_users() -> list:
    """Returns list of local accounts and system groups."""
    SKIP = {"guest", "wdagutilityaccount", "defaultaccount"}
    names = []
    try:
        users, _, _ = win32net.NetUserEnum(None, 0)
        for u in users:
            name = u.get("name", "")
            if name.lower() not in SKIP:
                names.append(name)
    except Exception:
        pass
    system_principals = ["Administratorzy", "Administrators", "SYSTEM",
                         "Users", "Users", "Wszyscy", "Everyone"]
    for p in system_principals:
        if p not in names:
            names.append(p)
    return names



def windows_select_user(parent=None) -> str:
    """Otwiera dialog wyboru lokalnego uzytkownika."""
    dlg = UserPickerDialog(title='Select owner', multi=False, parent=parent)
    if dlg.exec() == QtWidgets.QDialog.Accepted and dlg.selected_users:
        return dlg.selected_users[0].strip()
    return ''







# ---------------------------------------------------------------------------
# DIALOG: USER PICKER
# ---------------------------------------------------------------------------
class UserPickerDialog(QtWidgets.QDialog):
    """Dialog with list of local accounts instead of text field."""

    def __init__(self, title="Select User", multi=False, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(420, 480)
        self.setStyleSheet(DARK_STYLE)
        self.selected_users = []
        self._multi = multi
        self._build_ui()
        self._load_users()

    def _build_ui(self):
        layout = QtWidgets.QVBoxLayout(self)
        layout.setSpacing(8)
        layout.addWidget(QtWidgets.QLabel("Konta lokalne i grupy systemowe:"))

        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Szukaj...")
        self.filter_edit.textChanged.connect(self._filter)
        layout.addWidget(self.filter_edit)

        self.list_widget = QtWidgets.QListWidget()
        if self._multi:
            self.list_widget.setSelectionMode(
                QtWidgets.QAbstractItemView.ExtendedSelection)
        layout.addWidget(self.list_widget, 1)
        self.list_widget.doubleClicked.connect(self.accept)

        btn_row = QtWidgets.QHBoxLayout()
        btn_ok = QtWidgets.QPushButton("✅ Select")
        btn_ok.setObjectName("btnBlue")
        btn_ok.clicked.connect(self.accept)
        btn_cancel = QtWidgets.QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addStretch()
        btn_row.addWidget(btn_ok)
        btn_row.addWidget(btn_cancel)
        layout.addLayout(btn_row)

    def _load_users(self):
        self._all_users = get_local_users()
        self.list_widget.clear()
        for u in self._all_users:
            self.list_widget.addItem(u)
        if self.list_widget.count() > 0:
            self.list_widget.setCurrentRow(0)

    def _filter(self, text):
        self.list_widget.clear()
        for u in self._all_users:
            if text.lower() in u.lower():
                self.list_widget.addItem(u)

    def accept(self):
        self.selected_users = [i.text() for i in self.list_widget.selectedItems()]
        super().accept()



# ---------------------------------------------------------------------------
# HELPER: CHANGE OWNER WITH PRIVILEGES
# ---------------------------------------------------------------------------
def enable_privilege(priv_name: str) -> bool:
    try:
        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
        )
        luid = win32security.LookupPrivilegeValue(None, priv_name)
        win32security.AdjustTokenPrivileges(
            token, False, [(luid, win32security.SE_PRIVILEGE_ENABLED)])
        return True
    except Exception:
        return False


def _get_account_full_name(sid) -> str:
    user_name, domain, _ = win32security.LookupAccountSid(None, sid)
    return (domain + "\\" + user_name) if domain else user_name


def set_owner_with_privileges(path: str, new_sid) -> None:
    # Zmienia wlasciciela przez ctypes - omija ograniczenia pywin32 i PowerShell
    import ctypes, ctypes.wintypes as wt
    advapi = ctypes.windll.advapi32
    kernel  = ctypes.windll.kernel32

    SE_FILE_OBJECT       = 1
    OWNER_SECURITY_INFO  = 0x00000001
    TOKEN_ADJUST_PRIVS   = 0x0020
    TOKEN_QUERY          = 0x0008
    SE_PRIVILEGE_ENABLED = 0x00000002

    def _enable_priv(name):
        hToken = wt.HANDLE()
        kernel.OpenProcessToken(
            kernel.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVS | TOKEN_QUERY,
            ctypes.byref(hToken))
        luid = wt.LARGE_INTEGER()
        advapi.LookupPrivilegeValueW(None, name, ctypes.byref(luid))
        class LUID_ATTR(ctypes.Structure):
            _fields_ = [("Luid", wt.LARGE_INTEGER), ("Attr", wt.DWORD)]
        class TOKEN_P(ctypes.Structure):
            _fields_ = [("Count", wt.DWORD), ("Privs", LUID_ATTR * 1)]
        tp = TOKEN_P()
        tp.Count = 1
        tp.Privs[0].Luid = luid
        tp.Privs[0].Attr = SE_PRIVILEGE_ENABLED
        advapi.AdjustTokenPrivileges(
            hToken, False, ctypes.byref(tp), 0, None, None)
        kernel.CloseHandle(hToken)

    for p in ("SeYeseOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege"):
        _enable_priv(p)

    # Konwertuj pywin32 SID na bytes
    sid_bytes = bytes(new_sid)
    sid_buf = ctypes.create_string_buffer(sid_bytes)

    rc = advapi.SetNamedSecurityInfoW(
        ctypes.c_wchar_p(path),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFO,
        sid_buf,  # owner
        None,     # group
        None,     # dacl
        None      # sacl
    )

    if rc == 0:
        return  # ERROR_SUCCESS

    # Fallback: pywin32
    try:
        enable_privilege("SeYeseOwnershipPrivilege")
        enable_privilege("SeRestorePrivilege")
        enable_privilege("SeBackupPrivilege")
        win32security.SetNamedSecurityInfo(
            path, win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION,
            new_sid, None, None, None)
        return
    except Exception as e2:
        pass

    try:
        full_name = _get_account_full_name(new_sid)
    except Exception:
        full_name = "?"

    raise RuntimeError(
        "SetNamedSecurityInfo blad " + str(rc) + " dla '" + full_name + "'.")





def secure_home_folder(path: str, user_login: str) -> None:
    """
    Sets home folder ACL: access ONLY for owner + SYSTEM.
    Removes inheritance, blocks access for Users/Everyone.
    """
    enable_privilege("SeYeseOwnershipPrivilege")
    enable_privilege("SeRestorePrivilege")
    enable_privilege("SeBackupPrivilege")

    try:
        user_sid, _, _ = win32security.LookupAccountName(None, user_login)
    except Exception:
        return  # Account jeszcze nie istnieje — nie ustawiaj ACL

    try:
        system_sid = win32security.CreateWellKnownSid(
            win32security.WinLocalSystemSid, None)
    except Exception:
        system_sid, _, _ = win32security.LookupAccountName(None, "SYSTEM")

    # New DACL — owner only (full control) + SYSTEM (full control)
    new_dacl = win32security.ACL()
    new_dacl.AddAccessAllowedAce(
        win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, user_sid)
    new_dacl.AddAccessAllowedAce(
        win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, system_sid)

    # Apply without inheritance (PROTECTED_DACL = disable parent inheritance)
    win32security.SetNamedSecurityInfo(
        path,
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION |
        win32security.OWNER_SECURITY_INFORMATION |
        win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        user_sid,   # set owner
        None,
        new_dacl,
        None
    )


# ===========================================================================
# DIALOG: ADVANCED SECURITY SETTINGS
# ===========================================================================
class AdvancedSecurityDialog(QtWidgets.QDialog):
    """Okno Advanced Security Settings — wzorowane na oryginale NTFS Permissions Tools."""

    APPLY_OPTIONS = [
        "This folder only",
        "This folder,subfolders and files",
        "This folder and subfolders",
        "This folder and files",
        "Subfolders and files only",
        "Subfolders only",
        "Files only",
    ]

    def __init__(self, path: str, parent=None):
        super().__init__(parent)
        self.path = path
        self.setWindowTitle("Advanced Security Settings")
        self.setMinimumSize(950, 600)
        self.setStyleSheet(DARK_STYLE)
        self._ace_data = []
        self._build_ui()
        self._load()

    # ─────────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        lay = QtWidgets.QVBoxLayout(self)
        lay.setSpacing(6)

        # Header — Object name + Owner in one row
        hdr = QtWidgets.QFormLayout()
        hdr.setHorizontalSpacing(10)
        self.lbl_object = QtWidgets.QLineEdit(self.path)
        self.lbl_object.setReadOnly(True)
        self.lbl_owner = QtWidgets.QLineEdit("—")
        self.lbl_owner.setReadOnly(True)
        hdr.addRow("Object name:", self.lbl_object)
        hdr.addRow("Current Owner:", self.lbl_owner)
        lay.addLayout(hdr)

        # ── Tabela ACE: Type | Principal | Allow | Deny | Inherited From | Apply to | Remove ──
        self.ace_table = QtWidgets.QTableWidget(0, 7)
        self.ace_table.setHorizontalHeaderLabels([
            "Type", "Principal", "Allow", "Deny", "Inherited From", "Apply to", ""])
        hv = self.ace_table.horizontalHeader()
        hv.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        hv.setSectionResizeMode(1, QtWidgets.QHeaderView.Stretch)
        hv.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
        hv.setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeToContents)
        hv.setSectionResizeMode(5, QtWidgets.QHeaderView.ResizeToContents)
        hv.setSectionResizeMode(6, QtWidgets.QHeaderView.ResizeToContents)
        self.ace_table.verticalHeader().setVisible(False)
        self.ace_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.ace_table.setAlternatingRowColors(True)
        lay.addWidget(self.ace_table, 1)

        # ── Add user ───────────────────────────────────────────────────
        add_frame = QtWidgets.QGroupBox("Add Permission")
        add_lay = QtWidgets.QHBoxLayout(add_frame)
        add_lay.addWidget(QtWidgets.QLabel("User:"))

        self.add_user_combo = QtWidgets.QComboBox()
        self.add_user_combo.setMinimumWidth(180)
        self._reload_user_combo()
        add_lay.addWidget(self.add_user_combo, 1)

        btn_reload_u = QtWidgets.QPushButton("🔄")
        btn_reload_u.setFixedWidth(32)
        btn_reload_u.setToolTip("Refresh account list")
        btn_reload_u.clicked.connect(self._reload_user_combo)
        add_lay.addWidget(btn_reload_u)

        add_lay.addWidget(QtWidgets.QLabel("Access:"))
        self.add_access_combo = QtWidgets.QComboBox()
        self.add_access_combo.addItems([
            "Full Control",
            "Odczyt",
            "Odczyt i wykonanie",
            "Zapis",
            "Odczyt + Zapis",
            "Deny — Full Block",
        ])
        add_lay.addWidget(self.add_access_combo)

        add_lay.addWidget(QtWidgets.QLabel("Apply to:"))
        self.add_apply_combo = QtWidgets.QComboBox()
        self.add_apply_combo.addItems(self.APPLY_OPTIONS)
        self.add_apply_combo.setCurrentIndex(1)
        add_lay.addWidget(self.add_apply_combo)

        btn_add = QtWidgets.QPushButton("➕ Add")
        btn_add.setObjectName("btnGreen")
        btn_add.clicked.connect(self._add_ace_from_combo)
        add_lay.addWidget(btn_add)
        lay.addWidget(add_frame)

        # ── Checkboxy dziedziczenia ───────────────────────────────────────
        self.cb_include = QtWidgets.QCheckBox(
            "Include inheritable permissions from this object's parent")
        self.cb_replace = QtWidgets.QCheckBox(
            "Replace all child object permissions with inheritable permissions from this object")
        lay.addWidget(self.cb_include)
        lay.addWidget(self.cb_replace)

        # ── Przyciski dolne ───────────────────────────────────────────────
        btn_row = QtWidgets.QHBoxLayout()
        self.btn_change_owner = QtWidgets.QPushButton("Change Owner")
        self.btn_change_owner.clicked.connect(self._change_owner)
        btn_apply = QtWidgets.QPushButton("Apply")
        btn_apply.setObjectName("btnGreen")
        btn_apply.clicked.connect(self._apply)
        btn_apply.setEnabled(False)
        self.btn_apply = btn_apply
        btn_ok = QtWidgets.QPushButton("OK")
        btn_ok.setObjectName("btnBlue")
        btn_ok.clicked.connect(self._on_ok)
        btn_cancel = QtWidgets.QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)

        # Activate Apply when something changed
        self.ace_table.itemChanged.connect(lambda: self.btn_apply.setEnabled(True))

        btn_row.addWidget(self.btn_change_owner)
        btn_row.addStretch()
        btn_row.addWidget(btn_apply)
        btn_row.addWidget(btn_ok)
        btn_row.addWidget(btn_cancel)
        lay.addLayout(btn_row)

    # ─────────────────────────────────────────────────────────────────────────
    def _load(self):
        self.ace_table.setRowCount(0)
        self._ace_data = []
        self.btn_apply.setEnabled(False)
        try:
            sd = win32security.GetFileSecurity(
                self.path,
                win32security.DACL_SECURITY_INFORMATION |
                win32security.OWNER_SECURITY_INFORMATION
            )
            owner_sid = sd.GetSecurityDescriptorOwner()
            try:
                on, od, _ = win32security.LookupAccountSid(None, owner_sid)
                self.lbl_owner.setText(f"{od}\\{on}")
            except Exception:
                self.lbl_owner.setText(str(owner_sid))

            dacl = sd.GetSecurityDescriptorDacl()
            if not dacl:
                return

            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                header, mask, sid = ace
                try:
                    name, dom, _ = win32security.LookupAccountSid(None, sid)
                    principal = name
                except Exception:
                    principal = str(sid)

                is_deny = header[0] in [
                    win32security.ACCESS_DENIED_ACE_TYPE,
                    win32security.ACCESS_DENIED_OBJECT_ACE_TYPE
                ]
                is_inherited = bool(header[1] & win32security.INHERITED_ACE)
                # Inheritance source — parent or this object
                inherited_from = os.path.dirname(self.path) if is_inherited else ""

                self._insert_ace_row(principal, sid, mask, is_deny,
                                     is_inherited, inherited_from)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error",
                f"Cannot read permissions:\n{e}")

    def _insert_ace_row(self, principal: str, sid, mask: int,
                        is_deny: bool, is_inherited: bool,
                        inherited_from: str = ""):
        row = self.ace_table.rowCount()
        self.ace_table.insertRow(row)

        # Kol 0: Type (Allow/Deny)
        type_str = "Deny" if is_deny else "Allow"
        type_item = QtWidgets.QTableWidgetItem(type_str)
        type_item.setForeground(
            QtGui.QColor("#ff7b72") if is_deny else QtGui.QColor("#7ee787"))
        type_item.setTextAlignment(QtCore.Qt.AlignCenter)
        type_item.setFlags(type_item.flags() & ~QtCore.Qt.ItemIsEditable)
        self.ace_table.setItem(row, 0, type_item)

        # Kol 1: Principal
        p_item = QtWidgets.QTableWidgetItem(principal)
        p_item.setFlags(p_item.flags() & ~QtCore.Qt.ItemIsEditable)
        self.ace_table.setItem(row, 1, p_item)

        # Kol 2: Allow checkbox
        w_allow, cb_allow = centered_cb(not is_deny)
        self.ace_table.setCellWidget(row, 2, w_allow)

        # Kol 3: Deny checkbox
        w_deny, cb_deny = centered_cb(is_deny)
        self.ace_table.setCellWidget(row, 3, w_deny)

        def _sync_type(is_deny_now, ti=type_item):
            ti.setText("Deny" if is_deny_now else "Allow")
            ti.setForeground(QtGui.QColor(
                "#ff7b72" if is_deny_now else "#7ee787"))
            self.btn_apply.setEnabled(True)

        cb_allow.toggled.connect(lambda c, d=cb_deny: (d.setChecked(False), _sync_type(False)) if c else None)
        cb_deny.toggled.connect( lambda c, a=cb_allow: (a.setChecked(False), _sync_type(True))  if c else None)

        # Kol 4: Inherited From
        inh_item = QtWidgets.QTableWidgetItem(inherited_from if inherited_from else "—")
        inh_item.setForeground(QtGui.QColor("#8b949e" if is_inherited else "#c9d1d9"))
        inh_item.setFlags(inh_item.flags() & ~QtCore.Qt.ItemIsEditable)
        self.ace_table.setItem(row, 4, inh_item)

        # Kol 5: Apply to — combo
        apply_combo = QtWidgets.QComboBox()
        apply_combo.addItems(self.APPLY_OPTIONS)
        apply_combo.setCurrentIndex(1)  # "This folder,subfolders and files"
        apply_combo.currentIndexChanged.connect(lambda _: self.btn_apply.setEnabled(True))
        self.ace_table.setCellWidget(row, 5, apply_combo)

        # Kol 6: Remove
        btn_del = QtWidgets.QPushButton("✕")
        btn_del.setObjectName("btnRed")
        btn_del.setFixedWidth(32)
        btn_del.clicked.connect(self._delete_ace_row)
        self.ace_table.setCellWidget(row, 6, btn_del)

        self._ace_data.append({
            'sid': sid, 'mask': mask,
            'cb_allow': cb_allow, 'cb_deny': cb_deny,
            'inherited': is_inherited,
            'apply_combo': apply_combo,
        })

    def _reload_user_combo(self):
        current = self.add_user_combo.currentText()
        self.add_user_combo.blockSignals(True)
        self.add_user_combo.clear()
        for u in get_local_users():
            self.add_user_combo.addItem(u)
        idx = self.add_user_combo.findText(current)
        if idx >= 0:
            self.add_user_combo.setCurrentIndex(idx)
        self.add_user_combo.blockSignals(False)

    def _delete_ace_row(self):
        sender = self.sender()
        for r in range(self.ace_table.rowCount()):
            if self.ace_table.cellWidget(r, 6) is sender:
                self.ace_table.removeRow(r)
                if r < len(self._ace_data):
                    self._ace_data.pop(r)
                self.btn_apply.setEnabled(True)
                return

    def _add_ace_from_combo(self):
        name = self.add_user_combo.currentText().strip()
        if not name:
            return
        access_idx = self.add_access_combo.currentIndex()
        is_deny = (access_idx == 5)
        mask_map = {
            0: ntsecuritycon.FILE_ALL_ACCESS,
            1: ntsecuritycon.FILE_GENERIC_READ,
            2: ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_EXECUTE,
            3: ntsecuritycon.FILE_GENERIC_WRITE,
            4: ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_WRITE,
            5: ntsecuritycon.FILE_ALL_ACCESS,  # Deny
        }
        mask = mask_map.get(access_idx, ntsecuritycon.FILE_ALL_ACCESS)
        try:
            sid, _, _ = win32security.LookupAccountName(None, name)
            self._insert_ace_row(name, sid, mask, is_deny, False, "")
            self.btn_apply.setEnabled(True)
        except Exception as e:
            QtWidgets.QMessageBox.warning(
                self, "Error", f"Cannot find account \'{name}\':\n{e}")

    def _apply(self):
        enable_privilege("SeRestorePrivilege")
        enable_privilege("SeBackupPrivilege")
        try:
            new_dacl = win32security.ACL()
            for d in self._ace_data:
                is_deny = d['cb_deny'].isChecked()
                if is_deny:
                    new_dacl.AddAccessDeniedAce(
                        win32security.ACL_REVISION, d['mask'], d['sid'])
                else:
                    new_dacl.AddAccessAllowedAce(
                        win32security.ACL_REVISION, d['mask'], d['sid'])

            flags = win32security.DACL_SECURITY_INFORMATION
            if self.cb_replace.isChecked():
                flags |= win32security.PROTECTED_DACL_SECURITY_INFORMATION

            win32security.SetNamedSecurityInfo(
                self.path, win32security.SE_FILE_OBJECT,
                flags, None, None, new_dacl, None)

            self.btn_apply.setEnabled(False)
            QtWidgets.QMessageBox.information(self, "OK",
                "Permissions have been applied.")
            self._load()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error",
                f"Cannot apply permissions:\n{e}")

    def _on_ok(self):
        if self.btn_apply.isEnabled():
            self._apply()
        else:
            self.accept()

    def _change_owner(self):
        name = windows_select_user(self).strip()
        if not name:
            return
        try:
            new_sid, _, _ = win32security.LookupAccountName(None, name)
            set_owner_with_privileges(self.path, new_sid)
            QtWidgets.QMessageBox.information(
                self, "OK", f"Owner changed to: {name}")
            self._load()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error",
                f"Cannot change owner:\n{e}")


# ===========================================================================
# DIALOG: OPTIONS — Allow/ReadOnly/Deny with user list and Apply To
# ===========================================================================
class AccessOptionsDialog(QtWidgets.QDialog):
    """Dialog 'Options' wzorowany na NTFS Permissions Tools."""

    APPLY_FLAGS = {
        "This folder only":                    0x00000003,  # OI nie, CI nie  — tylko ten obiekt
        "This folder, subfolders and files":   0x00000013,  # OI+CI
        "This folder and subfolders":          0x00000012,  # CI only
        "This folder and files":               0x00000011,  # OI only (folder+pliki)
        "Subfolders and files only":           0x00000010,  # inherit only
        "Subfolders only":                     0x00000010,
        "Files only":                          0x00000003,
    }

    def __init__(self, mode: str, paths: list, parent=None):
        super().__init__(parent)
        self.mode = mode          # "allow" | "readonly" | "deny"
        self.paths = paths
        self.selected_user = ""
        self.apply_to = "This folder, subfolders and files"
        titles = {"allow": "Options — Allow Access",
                  "readonly": "Options — Read Only",
                  "deny": "Options — Deny Access"}
        self.setWindowTitle(titles.get(mode, "Options"))
        self.setMinimumWidth(420)
        self.setStyleSheet(DARK_STYLE)
        self._build_ui()

    def _build_ui(self):
        lay = QtWidgets.QVBoxLayout(self)
        lay.setSpacing(12)

        # ── User selection ──────────────────────────────────────────────
        name_row = QtWidgets.QHBoxLayout()
        name_row.addWidget(QtWidgets.QLabel("Name:"))
        self.user_combo = QtWidgets.QComboBox()
        self.user_combo.setMinimumWidth(200)
        for u in get_local_users():
            self.user_combo.addItem(u)
        name_row.addWidget(self.user_combo, 1)
        btn_reload = QtWidgets.QPushButton("🔄")
        btn_reload.setFixedWidth(32)
        btn_reload.setToolTip("Refresh list")
        btn_reload.clicked.connect(self._reload_users)
        name_row.addWidget(btn_reload)
        lay.addLayout(name_row)

        # ── Apply To ─────────────────────────────────────────────────────
        lay.addWidget(QtWidgets.QLabel("Apply To:"))
        self.apply_group = QtWidgets.QButtonGroup(self)
        apply_options = [
            "This folder only",
            "This folder, subfolders and files",
            "This folder and subfolders",
            "This folder and files",
            "Subfolders and files only",
            "Subfolders only",
            "Files only",
        ]
        for i, opt in enumerate(apply_options):
            rb = QtWidgets.QRadioButton(opt)
            if opt == "This folder, subfolders and files":
                rb.setChecked(True)
            self.apply_group.addButton(rb, i)
            lay.addWidget(rb)

        lay.addSpacing(8)

        # ── Przyciski ────────────────────────────────────────────────────
        btn_row = QtWidgets.QHBoxLayout()
        btn_ok = QtWidgets.QPushButton("OK")
        btn_ok.setObjectName("btnBlue")
        btn_ok.setMinimumWidth(90)
        btn_ok.clicked.connect(self._on_ok)
        btn_cancel = QtWidgets.QPushButton("Cancel")
        btn_cancel.setMinimumWidth(90)
        btn_cancel.clicked.connect(self.reject)
        btn_row.addStretch()
        btn_row.addWidget(btn_ok)
        btn_row.addWidget(btn_cancel)
        lay.addLayout(btn_row)

    def _reload_users(self):
        cur = self.user_combo.currentText()
        self.user_combo.blockSignals(True)
        self.user_combo.clear()
        for u in get_local_users():
            self.user_combo.addItem(u)
        idx = self.user_combo.findText(cur)
        if idx >= 0:
            self.user_combo.setCurrentIndex(idx)
        self.user_combo.blockSignals(False)

    def _on_ok(self):
        self.selected_user = self.user_combo.currentText().strip()
        btn = self.apply_group.checkedButton()
        self.apply_to = btn.text() if btn else "This folder, subfolders and files"
        self.accept()


# ===========================================================================
# NTFS TAB — main file/folder list
# ===========================================================================
class NtfsTab(QtWidgets.QWidget):
    """NTFS tab with file list, toolbar and columns."""

    def __init__(self, log_fn, parent=None):
        super().__init__(parent)
        self._log = log_fn
        self._current_path = ""
        self._build_ui()
        self._load_drives()

    def _build_ui(self):
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        # ── TOOLBAR ─────────────────────────────────────────────────────────
        toolbar = QtWidgets.QHBoxLayout()
        toolbar.setSpacing(4)

        def make_tool_btn(icon_char, label, color=None):
            btn = QtWidgets.QToolButton()
            btn.setText(f"  {icon_char}  {label}")
            btn.setToolButtonStyle(QtCore.Qt.ToolButtonTextOnly)
            if color:
                btn.setStyleSheet(
                    f"QToolButton {{ background: {color}; color: #fff; "
                    f"border: 1px solid {color}; border-radius: 6px; "
                    f"padding: 6px 10px; font-weight: bold; font-size: 11px; }}"
                    f"QToolButton:hover {{ opacity: 0.8; }}"
                )
            return btn

        self.btn_add      = make_tool_btn("📂", "Add Files or Folders")
        self.btn_allow    = make_tool_btn("✅", "Allow Access",  "#238636")
        self.btn_readonly = make_tool_btn("🔒", "Read Only",     "#9a6700")
        self.btn_deny     = make_tool_btn("🚫", "Deny Access",   "#8b1a1a")
        self.btn_owner    = make_tool_btn("👤", "Change Owner",  "#1f6feb")
        self.btn_advanced = make_tool_btn("⚙",  "Advanced",      "#444")

        self.btn_add.clicked.connect(self._browse_add)
        self.btn_allow.clicked.connect(lambda: self._set_access_quick("allow"))
        self.btn_readonly.clicked.connect(lambda: self._set_access_quick("readonly"))
        self.btn_deny.clicked.connect(lambda: self._set_access_quick("deny"))
        self.btn_owner.clicked.connect(self._change_owner_quick)
        self.btn_advanced.clicked.connect(self._open_advanced)

        for btn in [self.btn_add, self.btn_allow, self.btn_readonly,
                    self.btn_deny, self.btn_owner, self.btn_advanced]:
            toolbar.addWidget(btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        # ── PATH BAR ────────────────────────────────────────────────────────
        path_row = QtWidgets.QHBoxLayout()
        self.drive_combo = QtWidgets.QComboBox()
        self.drive_combo.setFixedWidth(130)
        self.drive_combo.currentIndexChanged.connect(self._on_drive_changed)
        path_row.addWidget(QtWidgets.QLabel("📁"))
        path_row.addWidget(self.drive_combo)

        self.path_edit = QtWidgets.QLineEdit()
        self.path_edit.setPlaceholderText("Folder path...")
        self.path_edit.returnPressed.connect(lambda: self._load_path(self.path_edit.text()))
        path_row.addWidget(self.path_edit, 1)

        btn_up = QtWidgets.QPushButton("⬆ Up")
        btn_up.clicked.connect(self._go_up)
        btn_refresh = QtWidgets.QPushButton("🔄")
        btn_refresh.setFixedWidth(36)
        btn_refresh.clicked.connect(lambda: self._load_path(self._current_path))
        path_row.addWidget(btn_up)
        path_row.addWidget(btn_refresh)
        layout.addLayout(path_row)

        # ── FILE/FOLDER TABLE ───────────────────────────────────────────────
        self.file_table = QtWidgets.QTableWidget(0, 6)
        self.file_table.setHorizontalHeaderLabels([
            "Name", "Type", "Date created", "File system",
            "Access rights of current user", "Owner"
        ])
        hv = self.file_table.horizontalHeader()
        hv.setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        hv.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        hv.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
        hv.setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeToContents)
        hv.setSectionResizeMode(5, QtWidgets.QHeaderView.Stretch)
        self.file_table.verticalHeader().setVisible(False)
        self.file_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.file_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.file_table.doubleClicked.connect(self._on_double_click)
        self.file_table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.file_table.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self.file_table, 1)

        # ── PASEK STATUSU ──────────────────────────────────────────────────
        status_row = QtWidgets.QHBoxLayout()
        self.lbl_status = QtWidgets.QLabel("Selected 0 / Total 0")
        self.lbl_status.setStyleSheet("color: #8b949e; font-size: 11px;")
        self.file_table.itemSelectionChanged.connect(self._update_status)
        status_row.addStretch()
        status_row.addWidget(self.lbl_status)
        layout.addLayout(status_row)

    # ── INICJALIZACJA ─────────────────────────────────────────────────────
    def _load_drives(self):
        self.drive_combo.blockSignals(True)
        self.drive_combo.clear()
        try:
            drives = win32api.GetLogicalDriveStrings().split('\000')
            for d in drives:
                d = d.strip()
                if not d:
                    continue
                try:
                    vol = win32api.GetVolumeInformation(d)
                    label = vol[0] or ""
                    letter = d.rstrip("\\")
                    display = f"{label} ({letter})" if label else letter
                except Exception:
                    display = d.rstrip("\\")
                self.drive_combo.addItem(display, d)
        except Exception:
            for ltr in "CDEFGHIJKLMNOPQRSTUVWXYZ":
                p = f"{ltr}:\\"
                if os.path.exists(p):
                    self.drive_combo.addItem(p, p)
        self.drive_combo.blockSignals(False)
        if self.drive_combo.count() > 0:
            self._on_drive_changed(0)

    def _on_drive_changed(self, idx):
        path = self.drive_combo.itemData(idx)
        if path:
            self._load_path(path)

    def _go_up(self):
        parent = os.path.dirname(self._current_path.rstrip("\\"))
        if parent and parent != self._current_path:
            self._load_path(parent)

    def _browse_add(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Wybierz folder")
        if path:
            self._load_path(path.replace("/", "\\"))

    # ── LOADING DIRECTORY CONTENTS ───────────────────────────────────────
    def _load_path(self, path: str):
        if not path:
            return
        path = path.replace("/", "\\")
        if not os.path.exists(path):
            self._log(f"Path does not exist: {path}", "#ff7b72")
            return

        self._current_path = path
        self.path_edit.setText(path)
        self.file_table.setRowCount(0)

        try:
            entries = []
            # If root drive, add all subfolders and files
            for name in os.listdir(path):
                full = os.path.join(path, name)
                entries.append((name, full))
        except PermissionError:
            self._log(f"No read permissions: {path}", "#e3b341")
            return
        except Exception as e:
            self._log(f"Error listowania: {e}", "#ff7b72")
            return

        # Sortuj: foldery najpierw, potem pliki, alfanumerycznie
        entries.sort(key=lambda x: (0 if os.path.isdir(x[1]) else 1, x[0].lower()))

        for name, full in entries:
            self._add_entry_row(name, full)

        self._update_status()
        self._log(f"Loaded: {path} ({len(entries)} items)")

    def _add_entry_row(self, name: str, full_path: str):
        """Adde jeden wiersz do tabeli."""
        is_dir = os.path.isdir(full_path)

        row = self.file_table.rowCount()
        self.file_table.insertRow(row)

        # Ikona + Nazwa
        icon = "📁" if is_dir else "📄"
        name_item = QtWidgets.QTableWidgetItem(f"{icon}  {name}")
        name_item.setData(QtCore.Qt.UserRole, full_path)
        self.file_table.setItem(row, 0, name_item)

        # Typ
        type_str = "Folder" if is_dir else "File"
        self.file_table.setItem(row, 1, QtWidgets.QTableWidgetItem(type_str))

        # Data utworzenia
        try:
            ctime = os.path.getctime(full_path)
            date_str = datetime.fromtimestamp(ctime).strftime("%Y-%m-%d %H:%M")
        except Exception:
            date_str = "—"
        self.file_table.setItem(row, 2, QtWidgets.QTableWidgetItem(date_str))

        # File system — check drive type
        fs_str = self._get_fs(full_path)
        self.file_table.setItem(row, 3, QtWidgets.QTableWidgetItem(fs_str))

        # Current user access rights
        access_str, access_color, allowed = self._get_access(full_path)
        access_item = QtWidgets.QTableWidgetItem(f"  {access_str}")
        access_item.setForeground(QtGui.QColor(access_color))
        self.file_table.setItem(row, 4, access_item)

        # Owner
        owner_str = self._get_owner(full_path)
        owner_item = QtWidgets.QTableWidgetItem(owner_str)
        owner_item.setForeground(QtGui.QColor("#8b949e"))
        self.file_table.setItem(row, 5, owner_item)

        # Row color if no access
        if not allowed:
            for col in range(6):
                item = self.file_table.item(row, col)
                if item:
                    item.setBackground(QtGui.QColor("#2d1515"))

    def _get_fs(self, path: str) -> str:
        try:
            root = os.path.splitdrive(path)[0] + "\\"
            info = win32api.GetVolumeInformation(root)
            return info[4]  # FileSystemName
        except Exception:
            return "—"

    def _get_access(self, path: str):
        """Checks current user rights via AccessCheck."""
        try:
            # Get current process token
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32security.TOKEN_QUERY | win32security.TOKEN_DUPLICATE)
            # Duplikuj na impersonation token
            imp_token = win32security.DuplicateToken(
                token, win32security.SecurityImpersonation)
            sd = win32security.GetFileSecurity(
                path,
                win32security.DACL_SECURITY_INFORMATION |
                win32security.OWNER_SECURITY_INFORMATION |
                win32security.GROUP_SECURITY_INFORMATION)
            # Check read access
            granted, result = win32security.AccessCheck(
                sd, imp_token,
                con.FILE_GENERIC_READ,
                win32security.MapGenericMask(
                    con.FILE_GENERIC_READ,
                    win32security.GenericMapping(
                        con.FILE_GENERIC_READ,
                        con.FILE_GENERIC_WRITE,
                        con.FILE_GENERIC_EXECUTE,
                        con.FILE_ALL_ACCESS)))
            return ("Allowed", "#7ee787", True) if result else ("Denied", "#ff7b72", False)
        except Exception:
            # Fallback — prosty test
            try:
                if os.path.isdir(path):
                    os.listdir(path)
                else:
                    open(path, 'rb').close()
                return "Allowed", "#7ee787", True
            except PermissionError:
                return "Denied", "#ff7b72", False
            except Exception:
                return "Allowed", "#7ee787", True

    def _get_owner(self, path: str) -> str:
        try:
            sd = win32security.GetFileSecurity(
                path, win32security.OWNER_SECURITY_INFORMATION)
            owner_sid = sd.GetSecurityDescriptorOwner()
            if owner_sid is None:
                return "—"
            try:
                name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
                name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
                # Return domain backslash name for local accounts
                return (domain + chr(92) + name) if domain else name
            except Exception:
                # Unrecognized SID — return string SID
                try:
                    return win32security.ConvertSidToStringSid(owner_sid)
                except Exception:
                    return "?"
        except PermissionError:
            return "(no access)"
        except Exception:
            return "—"

    # ── NAWIGACJA ─────────────────────────────────────────────────────────
    def _on_double_click(self, index):
        row = index.row()
        item = self.file_table.item(row, 0)
        if item:
            path = item.data(QtCore.Qt.UserRole)
            if path and os.path.isdir(path):
                self._load_path(path)

    def _update_status(self):
        total = self.file_table.rowCount()
        selected = len(set(i.row() for i in self.file_table.selectedItems()))
        self.lbl_status.setText(f"Selected {selected} / Total {total}")

    # ── MENU KONTEKSTOWE ──────────────────────────────────────────────────
    def _context_menu(self, pos):
        menu = QtWidgets.QMenu(self)
        menu.setStyleSheet("""
            QMenu { background: #161b22; color: #e6e6e6; border: 1px solid #30363d; }
            QMenu::item:selected { background: #1f6feb; }
            QMenu::separator { background: #30363d; height: 1px; }
        """)
        act_allow    = menu.addAction("✅  Allow Access")
        act_readonly = menu.addAction("🔒  Read Only")
        act_deny     = menu.addAction("🚫  Deny Access")
        menu.addSeparator()
        act_owner   = menu.addAction("👤  Change Owner")
        act_advanced = menu.addAction("⚙   Advanced Security Settings")
        menu.addSeparator()
        act_refresh = menu.addAction("🔄  Refresh")

        act_allow.triggered.connect(lambda: self._set_access_quick("allow"))
        act_readonly.triggered.connect(lambda: self._set_access_quick("readonly"))
        act_deny.triggered.connect(lambda: self._set_access_quick("deny"))
        act_owner.triggered.connect(self._change_owner_quick)
        act_advanced.triggered.connect(self._open_advanced)
        act_refresh.triggered.connect(lambda: self._load_path(self._current_path))

        menu.exec(self.file_table.viewport().mapToGlobal(pos))

    # ── OPERACJE NA UPRAWNIENIACH ─────────────────────────────────────────
    def _get_selected_paths(self):
        rows = set(i.row() for i in self.file_table.selectedItems())
        paths = []
        for r in rows:
            item = self.file_table.item(r, 0)
            if item:
                p = item.data(QtCore.Qt.UserRole)
                if p:
                    paths.append(p)
        return paths

    def _set_access_quick(self, mode: str):
        paths = self._get_selected_paths()
        if not paths:
            QtWidgets.QMessageBox.information(self, "Info",
                "Select files/folders from the list, then click an operation.")
            return

        # Open Options dialog with user list and Apply To
        dlg = AccessOptionsDialog(mode, paths, parent=self)
        if dlg.exec() != QtWidgets.QDialog.Accepted or not dlg.selected_user:
            return

        target = dlg.selected_user
        apply_to = dlg.apply_to
        recurse = apply_to != "This folder only"

        mode_names = {"allow": "Allow Access", "readonly": "Read Only", "deny": "Deny Access"}
        ok_count = 0

        # Collect paths to process (with subfolders if recurse)
        all_paths = []
        for path in paths:
            all_paths.append(path)
            if recurse and os.path.isdir(path):
                if "files" in apply_to.lower() or "subfolders" in apply_to.lower():
                    for root, dirs, files in os.walk(path):
                        if "subfolders" in apply_to.lower() or "files" in apply_to.lower():
                            for d in dirs:
                                all_paths.append(os.path.join(root, d))
                        if "files" in apply_to.lower():
                            for f in files:
                                all_paths.append(os.path.join(root, f))

        for path in all_paths:
            try:
                target_sid, _, _ = win32security.LookupAccountName(None, target)

                enable_privilege("SeRestorePrivilege")
                enable_privilege("SeBackupPrivilege")

                sd = win32security.GetFileSecurity(
                    path, win32security.DACL_SECURITY_INFORMATION)
                dacl = sd.GetSecurityDescriptorDacl() or win32security.ACL()
                new_dacl = win32security.ACL()

                # Rewrite existing ACEs (without target SID — avoid duplicates)
                for i in range(dacl.GetAceCount()):
                    ace = dacl.GetAce(i)
                    hdr, ace_mask, ace_sid = ace
                    if ace_sid != target_sid:
                        ace_type = hdr[0]
                        if ace_type == win32security.ACCESS_DENIED_ACE_TYPE:
                            new_dacl.AddAccessDeniedAce(
                                win32security.ACL_REVISION, ace_mask, ace_sid)
                        else:
                            new_dacl.AddAccessAllowedAce(
                                win32security.ACL_REVISION, ace_mask, ace_sid)

                # Add new ACE for selected user
                if mode == "allow":
                    new_dacl.AddAccessAllowedAce(
                        win32security.ACL_REVISION, con.FILE_ALL_ACCESS, target_sid)
                elif mode == "readonly":
                    read_mask = con.FILE_GENERIC_READ | con.FILE_GENERIC_EXECUTE
                    new_dacl.AddAccessAllowedAce(
                        win32security.ACL_REVISION, read_mask, target_sid)
                elif mode == "deny":
                    new_dacl.AddAccessDeniedAce(
                        win32security.ACL_REVISION, con.FILE_ALL_ACCESS, target_sid)

                win32security.SetNamedSecurityInfo(
                    path,
                    win32security.SE_FILE_OBJECT,
                    win32security.DACL_SECURITY_INFORMATION,
                    None, None, new_dacl, None)
                ok_count += 1
            except Exception as e:
                self._log(f"Error dla {os.path.basename(path)}: {e}", "#ff7b72")

        self._log(
            f"Applied '{mode_names[mode]}' [{apply_to}] for user '{target}' "
            f"— {ok_count}/{len(all_paths)} items.", "#7ee787")
        self._load_path(self._current_path)

    def _change_owner_quick(self):
        paths = self._get_selected_paths()
        if not paths:
            QtWidgets.QMessageBox.information(self, "Info",
                "Zaznacz pliki/foldery i kliknij Change Owner.")
            return

        name = windows_select_user(self).strip()
        if not name:
            return
        # Jesli zwrocono KOMPUTER\login — wyodrebnij sam login dla LookupAccountName
        # (LookupAccountName akceptuje oba formaty)

        # Lookupname — get SID once before the loop
        try:
            new_sid, _, _ = win32security.LookupAccountName(None, name)
        except Exception as e:
            self._log(f"Cannot find account '{name}': {e}", "#ff7b72")
            return

        ok_count = 0
        for path in paths:
            try:
                set_owner_with_privileges(path, new_sid)
                enable_privilege("SeBackupPrivilege")
                enable_privilege("SeRestorePrivilege")
                # set_owner_with_privileges already verifies internally
                self._log(f"Owner changed to '{name}' [{os.path.basename(path)}]", "#7ee787")
                ok_count += 1
            except Exception as e:
                self._log(f"Error changing owner {os.path.basename(path)}: {e}", "#ff7b72")

        self._log(f"Change Owner complete: {ok_count}/{len(paths)} items.", "#7ee787")
        self._load_path(self._current_path)

    def _open_advanced(self):
        paths = self._get_selected_paths()
        if not paths:
            # If nothing selected — open for current directory
            path = self._current_path
        else:
            path = paths[0]

        if not path:
            return

        dlg = AdvancedSecurityDialog(path, self)
        dlg.exec()
        self._load_path(self._current_path)


# ===========================================================================
# MAIN APPLICATION
# ===========================================================================
class AdminTool(QtWidgets.QMainWindow):
    # Per-user: HKCU (lub HKU\SID) - dziala natychmiast bez gpupdate
    REG_CD_GUID  = "{53f56308-b6bf-11d0-94f2-00a0c91efb8b}"
    REG_CD_BASE  = r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
    REG_CD       = r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}"
    REG_CDROM_SVC = r"SYSTEM\CurrentControlSet\Services\cdrom"

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Pro Admin Tool — NTFS & CD/DVD & Users")
        self.setMinimumSize(1400, 900)
        self.is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        self._cd_row_data = []
        self._build_ui()
        self.setStyleSheet(DARK_STYLE)
        self.refresh_all()

    # -----------------------------------------------------------------------
    def _build_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        root = QtWidgets.QVBoxLayout(central)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)
        self._build_status_bar(root)

        # LOG must be created BEFORE tabs, because NtfsTab calls _log during initizacji
        log_group = QtWidgets.QGroupBox("EVENT LOG")
        log_layout = QtWidgets.QVBoxLayout(log_group)
        self.log = QtWidgets.QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFixedHeight(105)
        btn_row = QtWidgets.QHBoxLayout()
        btn_clear = QtWidgets.QPushButton("Clear log")
        btn_clear.setFixedWidth(120)
        btn_clear.clicked.connect(self.log.clear)
        btn_row.addStretch()
        btn_row.addWidget(btn_clear)
        log_layout.addWidget(self.log)
        log_layout.addLayout(btn_row)

        self.tabs = QtWidgets.QTabWidget()
        root.addWidget(self.tabs, 1)

        self._build_tab_ntfs()
        self._build_tab_cd()
        self._build_tab_users_create()
        self._build_tab_users_manage()
        self._build_tab_recovery()

        root.addWidget(log_group)

    def _build_status_bar(self, parent_layout):
        bar = QtWidgets.QHBoxLayout()
        icon = "✅ ADMINISTRATOR MODE" if self.is_admin else "⚠️ NO ADMINISTRATOR PRIVILEGES"
        color = "#2ea043" if self.is_admin else "#e3b341"
        status = QtWidgets.QLabel(icon)
        status.setStyleSheet(
            f"color: {color}; font-weight: bold; padding: 4px 8px;"
            f"background: {color}22; border-radius: 4px;")
        btn_refresh = QtWidgets.QPushButton("🔄 Refresh all")
        btn_refresh.setObjectName("btnBlue")
        btn_refresh.clicked.connect(self.refresh_all)
        bar.addWidget(status)
        bar.addStretch()
        bar.addWidget(btn_refresh)
        parent_layout.addLayout(bar)

    # ===========================
    # NTFS TAB
    # ===========================
    def _build_tab_ntfs(self):
        self.ntfs_tab = NtfsTab(log_fn=self._log)
        self.tabs.addTab(self.ntfs_tab, "🔒  NTFS — Permissions")

    # ===========================
    # CD/DVD TAB
    # ===========================
    def _build_tab_cd(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(tab)
        layout.setSpacing(8)

        CD_GUID = "{53f56308-b6bf-11d0-94f2-00a0c91efb8b}"
        self._cd_guid        = CD_GUID
        self._cd_deny_types  = ["Deny_Execute", "Deny_Read", "Deny_Write"]
        self._cd_deny_labels = ["Deny Execute", "Deny Read", "Deny Write"]
        self._cd_buttons     = {}
        self._cd_user_rows   = {}
        self._gp_zasady      = list(zip(
            ["CD and DVD: Deny Execute Access",
             "CD and DVD: Deny Read Access",
             "CD and DVD: Deny Write Access"],
            self._cd_deny_types))
        self._gp_table = None
        self._gp_buttons = {}
        self.cb_global_read = self.cb_global_write = None
        self.cb_global_disable = self.cb_deny_execute = None
        self.cb_deny_read = self.cb_deny_write = None

        # Kontener na grupy — budowany dynamicznie przez _read_cd_policies
        self._cd_groups_container = QtWidgets.QWidget()
        self._cd_groups_layout    = QtWidgets.QVBoxLayout(self._cd_groups_container)
        self._cd_groups_layout.setSpacing(8)
        self._cd_groups_layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._cd_groups_container)

        btn_read = QtWidgets.QPushButton("🔍 Read from registry and Registry.pol")
        btn_read.clicked.connect(self._read_cd_policies)
        layout.addWidget(btn_read)
        layout.addStretch()
        self.tabs.addTab(tab, "💿  CD/DVD — Policy")


    # ===========================
    # TAB: CREATE ACCOUNTS
    # ===========================
    def _build_tab_users_create(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(tab)
        layout.setSpacing(10)

        common_group = QtWidgets.QGroupBox("COMMON SETTINGS FOR NEW ACCOUNTS")
        cg = QtWidgets.QGridLayout(common_group)

        cg.addWidget(QtWidgets.QLabel("Home folder drive:"), 0, 0)
        self.drive_combo_users = QtWidgets.QComboBox()
        self._populate_user_drives()
        self.drive_combo_users.setFixedWidth(90)
        cg.addWidget(self.drive_combo_users, 0, 1)
        cg.addWidget(QtWidgets.QLabel("Folder domowy: <dysk>:\\<login>  np. E:\\andrzej.w"), 0, 2)

        cg.addWidget(QtWidgets.QLabel("Password for all accounts:"), 1, 0)
        self.shared_pass = QtWidgets.QLineEdit()
        self.shared_pass.setEchoMode(QtWidgets.QLineEdit.Password)
        self.shared_pass.setPlaceholderText("Shared password for all accounts...")
        cg.addWidget(self.shared_pass, 1, 1, 1, 2)
        btn_eye = QtWidgets.QPushButton("👁")
        btn_eye.setFixedWidth(36)
        btn_eye.setCheckable(True)
        btn_eye.toggled.connect(lambda c: self.shared_pass.setEchoMode(
            QtWidgets.QLineEdit.Normal if c else QtWidgets.QLineEdit.Password))
        cg.addWidget(btn_eye, 1, 3)

        self.cb_force_change = QtWidgets.QCheckBox(
            "Force password change on first login (for all created accounts)")
        self.cb_force_change.setChecked(True)
        cg.addWidget(self.cb_force_change, 2, 0, 1, 4)
        layout.addWidget(common_group)

        list_group = QtWidgets.QGroupBox("ACCOUNTS TO CREATE")
        ll = QtWidgets.QVBoxLayout(list_group)
        hdr = QtWidgets.QHBoxLayout()
        hdr.addWidget(QtWidgets.QLabel("Konta do utworzenia (podaj loginy):"))
        hdr.addStretch()
        btn_plus = QtWidgets.QPushButton("+")
        btn_plus.setObjectName("btnPlus")
        btn_plus.setToolTip("Add kolejne konto")
        btn_plus.clicked.connect(self._add_user_row)
        hdr.addWidget(btn_plus)
        ll.addLayout(hdr)

        self.users_to_create = QtWidgets.QTableWidget(0, 4)
        self.users_to_create.setHorizontalHeaderLabels(
            ["Login", "Account Type", "Home folder (preview)", "Remove"])
        self.users_to_create.horizontalHeader().setSectionResizeMode(
            0, QtWidgets.QHeaderView.Stretch)
        self.users_to_create.horizontalHeader().setSectionResizeMode(
            1, QtWidgets.QHeaderView.ResizeToContents)
        self.users_to_create.horizontalHeader().setSectionResizeMode(
            2, QtWidgets.QHeaderView.Stretch)
        self.users_to_create.horizontalHeader().setSectionResizeMode(
            3, QtWidgets.QHeaderView.ResizeToContents)
        ll.addWidget(self.users_to_create)
        layout.addWidget(list_group, 1)

        btn_create = QtWidgets.QPushButton("👤  CREATE ALL ACCOUNTS IN LIST")
        btn_create.setObjectName("btnGreen")
        btn_create.setMinimumHeight(42)
        btn_create.clicked.connect(self._create_all_users)
        layout.addWidget(btn_create)

        self.tabs.addTab(tab, "➕  New Accounts")

    # ===========================
    # TAB: ACCOUNT MANAGEMENT
    # ===========================
    def _build_tab_users_manage(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(tab)
        layout.setSpacing(8)

        info = QtWidgets.QLabel(
            "Select an account from the list, then use the buttons below.")
        info.setStyleSheet("color: #8b949e; font-size: 11px; padding: 4px;")
        layout.addWidget(info)

        self.existing_table = QtWidgets.QTableWidget(0, 3)
        self.existing_table.setHorizontalHeaderLabels(["Login", "Groups / Rola", "Folder domowy"])
        hv_ex = self.existing_table.horizontalHeader()
        hv_ex.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        hv_ex.setSectionResizeMode(1, QtWidgets.QHeaderView.Stretch)
        hv_ex.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
        self.existing_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.existing_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.existing_table.setAlternatingRowColors(True)
        layout.addWidget(self.existing_table, 1)

        # Button bar
        btn_bar = QtWidgets.QHBoxLayout()
        btn_bar.setSpacing(8)

        btn_re = QtWidgets.QPushButton("🔍  Refresh")
        btn_re.clicked.connect(self._refresh_existing_users)

        btn_block = QtWidgets.QPushButton("🔒  Zablokuj / Odblokuj")
        btn_block.setObjectName("btnRed")
        btn_block.clicked.connect(self._toggle_block_account)

        btn_chpass = QtWidgets.QPushButton("🔑  Change password")
        btn_chpass.setObjectName("btnOrange")
        btn_chpass.clicked.connect(self._change_password_dialog)

        btn_del = QtWidgets.QPushButton("🗑  Delete account")
        btn_del.setObjectName("btnRed")
        btn_del.clicked.connect(self._delete_account)

        btn_bar.addWidget(btn_re)
        btn_bar.addWidget(btn_block)
        btn_bar.addWidget(btn_chpass)
        btn_bar.addWidget(btn_del)
        btn_bar.addStretch()
        layout.addLayout(btn_bar)

        self.tabs.addTab(tab, "👥  Account Management")

    # ===========================
    # TAB: SYSTEM RECOVERY
    # ===========================
    def _build_tab_recovery(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(tab)
        layout.setSpacing(12)

        # PUNKT PRZYWRACANIA
        rp_group = QtWidgets.QGroupBox("SYSTEM RESTORE POINT")
        rp_layout = QtWidgets.QVBoxLayout(rp_group)

        rp_info = QtWidgets.QLabel(
            "Tworzy punkt przywracania systemu Windows. "
            "Wymaga wlaczonej ochrony systemu na dysku C:\\. "
            "Punkt przywracania pozwala cofnac zmiany systemowe, sterowniki i rejestr.")
        rp_info.setWordWrap(True)
        rp_info.setStyleSheet("color: #8b949e; padding: 4px;")
        rp_layout.addWidget(rp_info)

        rp_form = QtWidgets.QHBoxLayout()
        rp_form.addWidget(QtWidgets.QLabel("Point description:"))
        self.rp_desc = QtWidgets.QLineEdit()
        self.rp_desc.setPlaceholderText("e.g. Before software installation...")
        self.rp_desc.setText("Restore point — Pro Admin Tool")
        rp_form.addWidget(self.rp_desc, 1)
        rp_layout.addLayout(rp_form)

        rp_type_row = QtWidgets.QHBoxLayout()
        rp_type_row.addWidget(QtWidgets.QLabel("Point type:"))
        self.rp_type_combo = QtWidgets.QComboBox()
        self.rp_type_combo.addItems([
            "APPLICATION_INSTALL (0) — instalacja aplikacji",
            "APPLICATION_UNINSTALL (1) — odinstalowanie",
            "DEVICE_DRIVER_INSTALL (10) — instalacja sterownika",
            "MODIFY_SETTINGS (12) — zmiana ustawien systemowych",
            "CANCELLED_OPERATION (13) — anulowana operacja",
        ])
        self.rp_type_combo.setCurrentIndex(3)
        rp_type_row.addWidget(self.rp_type_combo, 1)
        rp_layout.addLayout(rp_type_row)

        rp_btns = QtWidgets.QHBoxLayout()
        btn_create_rp = QtWidgets.QPushButton("🛡  Create restore point")
        btn_create_rp.setObjectName("btnGreen")
        btn_create_rp.setMinimumHeight(38)
        btn_create_rp.clicked.connect(self._create_restore_point)
        btn_open_rp = QtWidgets.QPushButton("🔧  Open system restore")
        btn_open_rp.clicked.connect(lambda: subprocess.Popen(["rstrui.exe"]))
        btn_sysprop = QtWidgets.QPushButton("⚙  System properties (protection)")
        btn_sysprop.clicked.connect(lambda: subprocess.Popen(["SystemPropertiesProtection.exe"]))
        rp_btns.addWidget(btn_create_rp)
        rp_btns.addWidget(btn_open_rp)
        rp_btns.addWidget(btn_sysprop)
        rp_btns.addStretch()
        rp_layout.addLayout(rp_btns)

        self.rp_status = QtWidgets.QLabel("")
        self.rp_status.setStyleSheet("font-size: 12px; padding: 4px;")
        rp_layout.addWidget(self.rp_status)
        layout.addWidget(rp_group)

        # DYSK ODZYSKIWANIA
        rd_group = QtWidgets.QGroupBox("RECOVERY DRIVE")
        rd_layout = QtWidgets.QVBoxLayout(rd_group)

        rd_info = QtWidgets.QLabel(
            "Tworzy dysk USB odzyskiwania systemu Windows. "
            "Wymagany pendrive minimum 8 GB (wszystkie dane zostana usuniete). "
            "Proces uruchamia wbudowany kreator systemu Windows — RecoveryDrive.exe.")
        rd_info.setWordWrap(True)
        rd_info.setStyleSheet("color: #8b949e; padding: 4px;")
        rd_layout.addWidget(rd_info)

        rd_warn = QtWidgets.QLabel("⚠  WARNING: All data on the selected USB drive will be PERMANENTLY DELETED!")
        rd_warn.setStyleSheet(
            "color: #ff7b72; font-weight: bold; padding: 6px 8px;"
            "background: #2d1515; border-radius: 4px;")
        rd_layout.addWidget(rd_warn)

        rd_btns = QtWidgets.QHBoxLayout()
        btn_rd = QtWidgets.QPushButton("💾  Launch recovery drive wizard")
        btn_rd.setObjectName("btnBlue")
        btn_rd.setMinimumHeight(38)
        btn_rd.clicked.connect(self._launch_recovery_drive)
        rd_btns.addWidget(btn_rd)
        rd_btns.addStretch()
        rd_layout.addLayout(rd_btns)
        layout.addWidget(rd_group)

        # NARZEDZIA DIAGNOSTYCZNE
        diag_group = QtWidgets.QGroupBox("DIAGNOSTIC AND REPAIR TOOLS")
        diag_layout = QtWidgets.QGridLayout(diag_group)
        diag_layout.setSpacing(8)

        tools = [
            ("💻  sfc /scannow",       "Scan and repair system files",
             ["cmd", "/c", "start", "cmd", "/k", "sfc /scannow"]),
            ("🔧  DISM /RestoreHealth", "Repair Windows image",
             ["cmd", "/c", "start", "cmd", "/k", "DISM /Online /Cleanup-Image /RestoreHealth"]),
            ("📋  Disk Management", "Open diskmgmt.msc",
             ["diskmgmt.msc"]),
            ("🛡  Windows Defender",    "Antivirus scan",
             ["cmd", "/c", "start", "ms-windows-defender:"]),
            ("📊  Event Viewer",     "System and error logs",
             ["eventvwr.msc"]),
            ("⚙  System Configuration","msconfig — services and startup",
             ["msconfig"]),
            ("📁  Disk Cleanup",   "cleanmgr — free up space",
             ["cleanmgr"]),
            ("🔌  Device Manager",   "devmgmt.msc",
             ["devmgmt.msc"]),
        ]
        for i, (label, tip, cmd) in enumerate(tools):
            btn = QtWidgets.QPushButton(label)
            btn.setToolTip(tip)
            btn.setMinimumHeight(34)
            btn.clicked.connect(lambda checked, c=cmd: self._run_tool(c))
            diag_layout.addWidget(btn, i // 2, i % 2)

        layout.addWidget(diag_group)
        layout.addStretch()
        self.tabs.addTab(tab, "🛡  System Recovery")
        # Tab visible
        self.tabs.setTabVisible(self.tabs.count() - 1, True)
    # -----------------------------------------------------------------------
    # HELPERS
    # -----------------------------------------------------------------------
    def _populate_user_drives(self):
        self.drive_combo_users.clear()
        try:
            drives = win32api.GetLogicalDriveStrings().split('\000')
            for d in drives:
                d = d.strip()
                if not d:
                    continue
                # d = "C:\" — bierzemy tylko litere i dwukropek
                letter = d[:2]  # "C:"
                self.drive_combo_users.addItem(letter)
        except Exception:
            for l in "CDEFGHIJKLMNOPQRSTUVWXYZ":
                if os.path.exists(f"{l}:\\"):
                    self.drive_combo_users.addItem(f"{l}:")

    def _home_path(self, login: str) -> str:
        drive = self.drive_combo_users.currentText()
        return f"{drive}\\{login}"

    def _log(self, text: str, color: str = "#c9d1d9"):
        ts = QtCore.QTime.currentTime().toString("HH:mm:ss")
        self.log.append(f'<span style="color:{color};">[{ts}] {text}</span>')

    # ================================================================
    # REJESTR CD/DVD — pomocnicze
    # ================================================================

    REG_EXPLORER = REG_CD  # alias do REG_CD (RemovableStorageDevices)

    def _reg_set(self, sid_str, deny_read, deny_write):
        """
        Zapisuje NoReadCDROM i NoCDBurning dla danego SID.
        Jesli profil nie jest zaladowany — laduje hive tymczasowo.
        """
        import os, tempfile
        key_path = f"HKU\\{sid_str}\\{self.REG_EXPLORER}"

        # Sprawdz czy SID jest zaladowany w HKU
        check = subprocess.run(
            ["reg", "query", f"HKU\\{sid_str}"],
            capture_output=True, encoding="utf-8", errors="replace", timeout=5)
        loaded = check.returncode == 0

        tmp_hive = None
        if not loaded:
            # Znajdz plik NTUSER.DAT uzytkownika
            try:
                uname, _, _ = win32security.LookupAccountSid(None,
                    win32security.ConvertStringSidToSid(sid_str))
                ntuser = None
                for base in [r"C:\Users", r"C:\Users"]:
                    p = os.path.join(base, uname, "NTUSER.DAT")
                    if os.path.exists(p):
                        ntuser = p
                        break
                if ntuser:
                    tmp_hive = f"TMP_HIVE_{sid_str.replace('-','_')}"
                    r = subprocess.run(
                        ["reg", "load", f"HKU\\{tmp_hive}", ntuser],
                        capture_output=True, encoding="utf-8", errors="replace", timeout=10)
                    if r.returncode == 0:
                        key_path = f"HKU\\{tmp_hive}\\{self.REG_EXPLORER}"
                    else:
                        tmp_hive = None
            except Exception:
                tmp_hive = None

        try:
            for vname, val in [("NoReadCDROM", 1 if deny_read else 0),
                                ("NoCDBurning", 1 if deny_write else 0)]:
                subprocess.run(
                    ["reg", "add", key_path, "/v", vname,
                     "/t", "REG_DWORD", "/d", str(val), "/f"],
                    capture_output=True, encoding="utf-8", errors="replace", timeout=10)
        finally:
            if tmp_hive:
                subprocess.run(
                    ["reg", "unload", f"HKU\\{tmp_hive}"],
                    capture_output=True, timeout=10)

    def _reg_get(self, sid_str):
        """Czyta NoReadCDROM i NoCDBurning dla SID — z zaladowanego lub plikowego hive."""
        import os
        key_path = f"HKU\\{sid_str}\\{self.REG_EXPLORER}"

        check = subprocess.run(
            ["reg", "query", f"HKU\\{sid_str}"],
            capture_output=True, encoding="utf-8", errors="replace", timeout=5)
        loaded = check.returncode == 0

        tmp_hive = None
        if not loaded:
            try:
                uname, _, _ = win32security.LookupAccountSid(None,
                    win32security.ConvertStringSidToSid(sid_str))
                ntuser = None
                for base in [r"C:\Users", r"C:\Users"]:
                    p = os.path.join(base, uname, "NTUSER.DAT")
                    if os.path.exists(p):
                        ntuser = p
                        break
                if ntuser:
                    tmp_hive = f"TMP_HIVE_{sid_str.replace('-','_')}"
                    r = subprocess.run(
                        ["reg", "load", f"HKU\\{tmp_hive}", ntuser],
                        capture_output=True, encoding="utf-8", errors="replace", timeout=10)
                    if r.returncode == 0:
                        key_path = f"HKU\\{tmp_hive}\\{self.REG_EXPLORER}"
                    else:
                        tmp_hive = None
            except Exception:
                tmp_hive = None

        deny_r = deny_w = False
        try:
            for vname in ["NoReadCDROM", "NoCDBurning"]:
                r = subprocess.run(
                    ["reg", "query", key_path, "/v", vname],
                    capture_output=True, encoding="utf-8", errors="replace", timeout=5)
                if r.returncode == 0:
                    for line in r.stdout.splitlines():
                        parts = line.split()
                        if vname in parts and "REG_DWORD" in parts:
                            val = int(parts[-1], 16) == 1
                            if vname == "NoReadCDROM": deny_r = val
                            else: deny_w = val
        finally:
            if tmp_hive:
                subprocess.run(
                    ["reg", "unload", f"HKU\\{tmp_hive}"],
                    capture_output=True, timeout=10)
        return deny_r, deny_w

    # Aliasy dla kompatybilnosci
    def _gp_reg_query(self, vname):
        """Czyta stan zasady GP przez winreg.
        Zwraca: (exists: bool, value: int)
        exists=False oznacza brak wartosci (Not Configured w gpedit).
        exists=True, value=0 oznacza Disabled.
        exists=True, value=1 oznacza Enabled.
        """
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, self.REG_CD, 0, winreg.KEY_READ)
            try:
                val, _ = winreg.QueryValueEx(key, vname)
                winreg.CloseKey(key)
                return True, int(val)
            except FileNotFoundError:
                winreg.CloseKey(key)
                return False, 0  # klucz istnieje ale wartosci brak
        except FileNotFoundError:
            return False, 0  # caly klucz nie istnieje
        except Exception:
            return False, 0

    def _gp_reg_write(self, vname, value):
        """Zapisuje zasade GP do rejestru i Registry.pol (zapis binarny)."""
        # 1. Rejestr
        full = "HKLM\\" + self.REG_CD
        r = subprocess.run(
            ["reg", "add", full, "/v", vname, "/t", "REG_DWORD",
             "/d", str(value), "/f"],
            capture_output=True, encoding="utf-8", errors="replace", timeout=10)
        if r.returncode != 0:
            self._log(f"reg add blad: {r.stderr.strip() or r.stdout.strip()}", "#ff7b72")
            return
        # 2. Registry.pol — zapis bezposredni do pliku GP
        self._write_pol(vname, value)

    def _gp_reg_delete(self, vname):
        """Usuwa zasade GP z rejestru i Registry.pol."""
        full = "HKLM\\" + self.REG_CD
        subprocess.run(
            ["reg", "delete", full, "/v", vname, "/f"],
            capture_output=True, encoding="utf-8", errors="replace", timeout=10)
        self._write_pol(vname, None)  # None = usun z pol

    def _write_pol(self, vname, value):
        """
        Zapisuje/usuwa wartosc w Registry.pol — pliku ktory czyta gpedit.
        Format pol: [u'sciezka';u'wartosc';typ;dlugosc;dane]
        Naglowek: 50 52 65 67 01 00 00 00
        """
        import struct, os
        pol_path = r"C:\Windows\System32\GroupPolicy\Machine\Registry.pol"
        reg_key  = "Software\\Policies\\Microsoft\\Windows\\RemovableStorageDevices\\" \
                   "{53f56308-b6bf-11d0-94f2-00a0c91efb8b}"
        HEADER = b"PReg\x01\x00\x00\x00"

        # Wczytaj istniejacy plik lub stworz nowy
        try:
            with open(pol_path, "rb") as f:
                data = f.read()
            if not data.startswith(b"PReg"):
                data = HEADER
        except FileNotFoundError:
            data = HEADER
            os.makedirs(os.path.dirname(pol_path), exist_ok=True)

        # Parsuj istniejace wpisy
        entries = []
        pos = 8  # po naglowku
        while pos < len(data) - 1:
            if data[pos:pos+2] != b"[\x00":
                break
            pos += 2
            end = data.find(b"]\x00", pos)
            if end < 0:
                break
            entry_raw = data[pos:end]
            entries.append(entry_raw)
            pos = end + 2

        # Dekoduj i filtruj stary wpis dla tego vname
        def decode_entry(raw):
            parts = raw.split(b";\x00")
            if len(parts) >= 2:
                try:
                    k = raw.split(b";\x00")[0].decode("utf-16-le")
                    v = raw.split(b";\x00")[1].decode("utf-16-le")
                    return k, v
                except Exception:
                    pass
            return None, None

        new_entries = []
        for e in entries:
            k, v = decode_entry(e)
            if k and k.lower() == reg_key.lower() and v == vname:
                continue  # usun stary wpis
            new_entries.append(e)

        # Add nowy wpis jesli value nie jest None
        if value is not None:
            key_enc   = (reg_key + "\x00").encode("utf-16-le")
            vname_enc = (vname   + "\x00").encode("utf-16-le")
            val_bytes = struct.pack("<I", int(value))
            entry = (key_enc + b";\x00" +
                     vname_enc + b";\x00" +
                     b"\x04\x00\x00\x00;\x00" +           # typ REG_DWORD
                     struct.pack("<I", 4) + b";\x00" +    # dlugosc 4 bajty
                     val_bytes)
            new_entries.append(entry)

        # Zbuduj nowy plik
        out = HEADER
        for e in new_entries:
            out += b"[\x00" + e + b"]\x00"

        try:
            with open(pol_path, "wb") as f:
                f.write(out)
            self._log(f"Registry.pol zaktualizowany ({vname}).", "#8b949e")
        except Exception as ex:
            self._log(f"Blad zapisu Registry.pol: {ex}", "#ff7b72")

    def _reg_read_raw(self, path, value_name):
        return self._gp_reg_query(value_name)

    def _reg_read(self, hive_str, path, value_name):
        _, val = self._gp_reg_query(value_name)
        return val

    def _reg_write(self, hive_str, path, value_name, value):
        self._gp_reg_write(value_name, value)
        return True

    def _reg_delete_value(self, hive_str, path, value_name):
        self._gp_reg_delete(value_name)

    def _toggle_gp(self, vname):
        """Przelacza zasade: Enabled(1) <-> Disabled(0), jak gpedit."""
        exists, val = self._gp_reg_query(vname)
        new_val = 0 if (exists and val == 1) else 1
        self._gp_reg_write(vname, new_val)
        stan = "Enabled" if new_val == 1 else "Disabled"
        clr  = "#ff7b72" if new_val == 1 else "#e3b341"
        self._log(f"{vname}: {stan}", clr)
        self._read_global_cd()

    def _cd_reg_path(self):
        return ("SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices\\"
                + self._cd_guid)

    def _cd_query(self, hive_key, dtype):
        hive_obj = (winreg.HKEY_LOCAL_MACHINE if hive_key == "HKLM"
                    else winreg.HKEY_CURRENT_USER)
        try:
            key = winreg.OpenKey(hive_obj, self._cd_reg_path(), 0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(key, dtype)
            winreg.CloseKey(key)
            return int(val)
        except Exception:
            return 0

    def _cd_write(self, hive_key, dtype, value, pol_path):
        hive_str = "HKLM" if hive_key == "HKLM" else "HKCU"
        path = self._cd_reg_path()
        subprocess.run(
            ["reg", "add", hive_str + "\\" + path,
             "/v", dtype, "/t", "REG_DWORD", "/d", str(value), "/f"],
            capture_output=True, encoding="utf-8", errors="replace", timeout=10)
        self._pol_write_entry(pol_path, path, dtype, value)

    def _pol_write_entry(self, pol_path, reg_key, vname, value):
        import struct, os
        HEADER = b"PReg\x01\x00\x00\x00"
        try:
            with open(pol_path, "rb") as f:
                data = f.read()
            if not data.startswith(b"PReg"):
                data = HEADER
        except FileNotFoundError:
            data = HEADER
            os.makedirs(os.path.dirname(pol_path), exist_ok=True)
        entries, pos = [], 8
        while pos < len(data) - 1:
            if data[pos:pos+2] != b"[\x00":
                break
            pos += 2
            end = data.find(b"]\x00", pos)
            if end < 0:
                break
            entries.append(data[pos:end])
            pos = end + 2
        new_entries = []
        for e in entries:
            parts = e.split(b";\x00")
            try:
                k = parts[0].decode("utf-16-le").rstrip("\x00")
                v = parts[1].decode("utf-16-le").rstrip("\x00")
                if k.lower() == reg_key.lower() and v == vname:
                    continue
            except Exception:
                pass
            new_entries.append(e)
        if value is not None:
            entry = ((reg_key + "\x00").encode("utf-16-le") + b";\x00" +
                     (vname   + "\x00").encode("utf-16-le") + b";\x00" +
                     b"\x04\x00\x00\x00;\x00" +
                     struct.pack("<I", 4) + b";\x00" +
                     struct.pack("<I", int(value)))
            new_entries.append(entry)
        out = HEADER + b"".join(b"[\x00" + e + b"]\x00" for e in new_entries)
        try:
            with open(pol_path, "wb") as f:
                f.write(out)
        except Exception as ex:
            self._log(f"Error writing .pol: {ex}", "#ff7b72")

    # Stale dwie konfiguracje identyczne z gpedit
    _CD_CONFIGS = [
        ("Computer Configuration",
         "HKLM",
         r"C:\Windows\System32\GroupPolicy\Machine\Registry.pol",
         ["Deny_Execute", "Deny_Read", "Deny_Write"]),
        ("User Configuration",
         "HKCU",
         r"C:\Windows\System32\GroupPolicy\User\Registry.pol",
         ["Deny_Read", "Deny_Write"]),
    ]

    def _toggle_cd_config(self, hive_key, dtype, pol_path):
        val = self._cd_query(hive_key, dtype)
        self._cd_write(hive_key, dtype, 0 if val == 1 else 1, pol_path)
        self._log(
            f"{hive_key} {dtype}: {'Enabled' if val == 0 else 'Disabled'}",
            "#ff7b72" if val == 0 else "#7ee787")
        self._read_cd_policies()

    def _read_cd_policies(self):
        # Odbuduj przyciski jesli potrzeba
        if not self._cd_buttons:
            self._rebuild_cd_ui()
        for label, hive_key, pol_path, dtypes in self._CD_CONFIGS:
            for dtype in dtypes:
                btn = self._cd_buttons.get((hive_key, dtype))
                if not btn:
                    continue
                val = self._cd_query(hive_key, dtype)
                dlabel = self._cd_deny_labels[self._cd_deny_types.index(dtype)]
                self._cd_update_btn(btn, dlabel, val)

    def _rebuild_cd_ui(self):
        """Buduje przyciski w kontenerze."""
        while self._cd_groups_layout.count():
            item = self._cd_groups_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._cd_buttons = {}
        for cfg_label, hive_key, pol_path, dtypes in self._CD_CONFIGS:
            grp = QtWidgets.QGroupBox(cfg_label)
            grp.setStyleSheet("QGroupBox { color:#58a6ff; font-weight:bold; }")
            grp_l = QtWidgets.QHBoxLayout(grp)
            grp_l.setSpacing(8)
            for dtype in dtypes:
                dlabel = self._cd_deny_labels[self._cd_deny_types.index(dtype)]
                btn = QtWidgets.QPushButton(f"{dlabel}\nDisabled")
                btn.setFixedHeight(44)
                btn.setStyleSheet(
                    "background:#2d333b; color:#8b949e; "
                    "border:1px solid #444; border-radius:4px;")
                btn.clicked.connect(
                    lambda checked, h=hive_key, d=dtype, p=pol_path:
                        self._toggle_cd_config(h, d, p))
                self._cd_buttons[(hive_key, dtype)] = btn
                grp_l.addWidget(btn)
            self._cd_groups_layout.addWidget(grp)

    def _cd_update_btn(self, btn, label, val):
        if val == 1:
            btn.setText(f"{label}\nEnabled")
            btn.setStyleSheet(
                "background:#c0392b; color:white; "
                "font-weight:bold; border-radius:4px;")
        else:
            btn.setText(f"{label}\nDisabled")
            btn.setStyleSheet(
                "background:#2d333b; color:#8b949e; "
                "border:1px solid #444; border-radius:4px;")

    def _read_global_cd(self):
        self._read_cd_policies()

    def _read_dev_policies(self, hive=None):
        self._read_cd_policies()

    def _toggle_cd_policy(self, scope, dtype, pol_sub=None):
        for _, hive_key, pol_path, dtypes in self._CD_CONFIGS:
            if hive_key == scope and dtype in dtypes:
                self._toggle_cd_config(hive_key, dtype, pol_path)
                return

    def _toggle_gp(self, vname):
        self._toggle_cd_config("HKLM", vname,
            r"C:\Windows\System32\GroupPolicy\Machine\Registry.pol")

    def refresh_all(self):
        self._read_global_cd()
        self._read_cd_policies()
        self._refresh_existing_users()
        self._log("All data refreshed.", "#58a6ff")

    def _get_local_groups(self):
        """Pobiera lokalne grupy z lista czlonkow."""
        result = []
        try:
            groups, _, _ = win32net.NetLocalGroupEnum(None, 1)
            for g in groups:
                gname = g["name"]
                try:
                    sid, _, _ = win32security.LookupAccountName(None, gname)
                    sid_str = win32security.ConvertSidToStringSid(sid)
                except Exception:
                    sid_str = "?"
                try:
                    mraw, _, _ = win32net.NetLocalGroupGetMembers(None, gname, 3)
                    members = ", ".join(m["domainandname"].split("\\")[-1]
                                        for m in mraw) if mraw else "—"
                except Exception:
                    members = "?"
                result.append({"name": gname, "sid": sid_str, "members": members})
        except Exception as e:
            self._log(f"Blad pobierania grup: {e}", "#ff7b72")
        return result

    def _read_users_cd(self):
        """Odczytuje blokady CD/DVD per grupa — sprawdza kazdy profil czlonkow."""
        self.cd_table.setRowCount(0)
        self._cd_row_data = []
        for g in self._get_local_groups():
            # Sprawdz blokade u pierwszego czlonka grupy
            dr, dw = False, False
            try:
                mraw, _, _ = win32net.NetLocalGroupGetMembers(None, g["name"], 3)
                for m in mraw:
                    login = m["domainandname"].split("\\")[-1]
                    try:
                        sid, _, _ = win32security.LookupAccountName(None, login)
                        sid_str = win32security.ConvertSidToStringSid(sid)
                        dr, dw = self._reg_get(sid_str)
                        break  # wystarczy pierwszy czlonek
                    except Exception:
                        continue
            except Exception:
                pass

            row = self.cd_table.rowCount()
            self.cd_table.insertRow(row)
            name_item = QtWidgets.QTableWidgetItem(g["name"])
            name_item.setForeground(QtGui.QColor("#58a6ff"))
            self.cd_table.setItem(row, 0, name_item)
            members_item = QtWidgets.QTableWidgetItem(g["members"])
            members_item.setForeground(QtGui.QColor("#8b949e"))
            self.cd_table.setItem(row, 1, members_item)
            wr, cb_r = centered_cb(dr)
            ww, cb_w = centered_cb(dw)
            self.cd_table.setCellWidget(row, 2, wr)
            self.cd_table.setCellWidget(row, 3, ww)
            if dr or dw:
                for col in range(2):
                    item = self.cd_table.item(row, col)
                    if item: item.setForeground(QtGui.QColor("#ff7b72"))
            self._cd_row_data.append({"group": g["name"], "sid": g["sid"],
                                       "cb_r": cb_r, "cb_w": cb_w})
        self._log(f"Odczytano blokady CD dla {len(self._cd_row_data)} grup.", "#8b949e")

    def _save_users_cd(self):
        """Zapisuje blokady CD dla wszystkich czlonkow kazdej grupy przez reg load."""
        total_ok = 0
        total_all = 0
        for d in self._cd_row_data:
            block_r = d["cb_r"].isChecked()
            block_w = d["cb_w"].isChecked()
            try:
                mraw, _, _ = win32net.NetLocalGroupGetMembers(None, d["group"], 3)
                for m in mraw:
                    login = m["domainandname"].split("\\")[-1]
                    try:
                        sid, _, _ = win32security.LookupAccountName(None, login)
                        sid_str = win32security.ConvertSidToStringSid(sid)
                        total_all += 1
                        self._reg_set(sid_str, block_r, block_w)
                        total_ok += 1
                    except Exception as e:
                        self._log(f"  Pominieto {login}: {e}", "#e3b341")
            except Exception as e:
                self._log(f"Blad grupy {d['group']}: {e}", "#ff7b72")
        self._log(
            f"Zapisano blokady CD dla {total_ok}/{total_all} kont "
            f"({len(self._cd_row_data)} grup). Efekt po relogowaniu.", "#7ee787")
        self._read_users_cd()

    def _unblock_all_cd(self):
        for d in self._cd_row_data:
            d["cb_r"].setChecked(False)
            d["cb_w"].setChecked(False)
        self._log("Odznaczono wszystkie blokady — kliknij Save aby zatwierdzic.", "#e3b341")

    # ── USERS ───────────────────────────────────────────────────────────
    def _add_user_row(self):
        row = self.users_to_create.rowCount()
        self.users_to_create.insertRow(row)

        # Kolumna 0: Login
        login_w = QtWidgets.QLineEdit()
        login_w.setPlaceholderText("np. andrzej.w")
        login_w.setStyleSheet(
            "background: #161b22; color: #e6e6e6; border: 1px solid #30363d;"
            "border-radius: 4px; padding: 3px;")
        self.users_to_create.setCellWidget(row, 0, login_w)

        # Kolumna 1: Account Type
        type_combo = QtWidgets.QComboBox()
        type_combo.addItem("👤 Standard User", "user")
        type_combo.addItem("🔑 Administrator", "admin")
        type_combo.setCurrentIndex(0)
        self.users_to_create.setCellWidget(row, 1, type_combo)

        # Kolumna 2: Home folder (preview)
        preview_item = QtWidgets.QTableWidgetItem("—")
        preview_item.setFlags(preview_item.flags() & ~QtCore.Qt.ItemIsEditable)
        preview_item.setForeground(QtGui.QColor("#8b949e"))
        login_w.textChanged.connect(lambda txt, pi=preview_item:
            pi.setText(self._home_path(txt.strip()) if txt.strip() else "—"))
        self.drive_combo_users.currentTextChanged.connect(
            lambda _, lw=login_w, pi=preview_item:
            pi.setText(self._home_path(lw.text().strip()) if lw.text().strip() else "—"))
        self.users_to_create.setItem(row, 2, preview_item)

        # Kolumna 3: Remove
        btn_del = QtWidgets.QPushButton("✕")
        btn_del.setObjectName("btnRed")
        btn_del.setFixedWidth(36)
        btn_del.clicked.connect(lambda _, r=row: self._remove_row(r))
        self.users_to_create.setCellWidget(row, 3, btn_del)

        self.users_to_create.scrollToBottom()
        login_w.setFocus()

    def _remove_row(self, target_row):
        sender_btn = self.sender()
        if sender_btn:
            for r in range(self.users_to_create.rowCount()):
                btn_widget = self.users_to_create.cellWidget(r, 3)  # kolumna 3 = Remove
                if btn_widget is sender_btn:
                    self.users_to_create.removeRow(r)
                    return
        if target_row < self.users_to_create.rowCount():
            self.users_to_create.removeRow(target_row)

    def _create_all_users(self):
        password = self.shared_pass.text()
        if not password:
            QtWidgets.QMessageBox.warning(self, "Error", "Enter a shared password!")
            return
        rows = self.users_to_create.rowCount()
        if rows == 0:
            QtWidgets.QMessageBox.information(self, "Info", "Lista kont jest pusta.")
            return
        force = self.cb_force_change.isChecked()
        created = errors = 0

        for r in range(rows):
            login_w = self.users_to_create.cellWidget(r, 0)
            type_combo = self.users_to_create.cellWidget(r, 1)
            if not login_w:
                continue
            login = login_w.text().strip()
            if not login:
                continue
            is_admin = (type_combo.currentData() == "admin") if type_combo else False
            home = self._home_path(login)

            try:
                # Step 1: Create home folder
                if home and not os.path.exists(home):
                    os.makedirs(home, exist_ok=True)

                # Step 2: NetUserAdd level 1 — simplest and always works
                # priv MUST be USER_PRIV_USER (1) — Windows sets the rest
                info1 = {
                    'name':       login,
                    'password':   password,
                    'priv':       1,          # USER_PRIV_USER — hardcoded, win32netcon may have wrong value
                    'home_dir':   home,
                    'comment':    '',
                    'flags':      0x0200 | 0x0001,  # UF_NORMAL_ACCOUNT | UF_SCRIPT
                    'script_path': '',
                }
                win32net.NetUserAdd(None, 1, info1)

                # Step 3: Force password change (level 1003 has no password_expired,
                #         using level 3 only to set this field)
                if force:
                    try:
                        info3 = win32net.NetUserGetInfo(None, login, 3)
                        info3['password_expired'] = 1
                        win32net.NetUserSetInfo(None, login, 3, info3)
                    except Exception as ef:
                        self._log(f"  ⚠ Cannot set password enforcement for '{login}': {ef}", "#e3b341")

                # Step 4: Secure home folder — owner + SYSTEM only
                if home and os.path.exists(home):
                    try:
                        secure_home_folder(home, login)
                        self._log(f"  🔒 Folder domowy zabezpieczony: {home}", "#58a6ff")
                    except Exception as es:
                        self._log(f"  ⚠ Cannot secure folder: {es}", "#e3b341")

                # Krok 5: Add do grupy Administratorzy lub Users
                if is_admin:
                    try:
                        win32net.NetLocalGroupAddMembers(None, "Administratorzy", 3,
                            [{'domainandname': login}])
                    except Exception:
                        try:  # Angielska nazwa grupy (EN Windows)
                            win32net.NetLocalGroupAddMembers(None, "Administrators", 3,
                                [{'domainandname': login}])
                        except Exception as eg:
                            self._log(f"  ⚠ Cannot add to Administrators: {eg}", "#e3b341")
                else:
                    # Add to Users group (may already be automatic — but explicit is safer)
                    try:
                        win32net.NetLocalGroupAddMembers(None, "Users", 3,
                            [{'domainandname': login}])
                    except Exception:
                        try:
                            win32net.NetLocalGroupAddMembers(None, "Users", 3,
                                [{'domainandname': login}])
                        except Exception:
                            pass  # Brak grupy Users — OK, konto i tak istnieje

                typ_str = "Administrator" if is_admin else "User"
                self._log(f"✅ Account created [{typ_str}]: {login} → {home}", "#7ee787")
                created += 1

            except win32net.error as e:
                if e.args[0] == 2224:
                    self._log(f"⚠ Account '{login}' already exists — skipped.", "#e3b341")
                else:
                    self._log(f"❌ Error '{login}': {e}", "#ff7b72")
                    errors += 1
            except Exception as e:
                self._log(f"❌ Error '{login}': {e}", "#ff7b72")
                errors += 1

        msg = f"Completed: {created} accounts created, {errors} errors."
        self._log(msg, "#7ee787" if errors == 0 else "#e3b341")
        QtWidgets.QMessageBox.information(self, "Wynik", msg)
        self.users_to_create.setRowCount(0)
        self._refresh_existing_users()
        self._read_users_cd()

    def _refresh_existing_users(self):
        self.existing_table.setRowCount(0)
        SKIP = {'guest', 'wdagutilityaccount', 'defaultaccount'}
        try:
            users, _, _ = win32net.NetUserEnum(None, 3)
            for u in users:
                name = u.get('name', '')
                if name.lower() in SKIP:
                    continue
                flags = u.get('flags', 0)
                is_disabled = bool(flags & win32netcon.UF_ACCOUNTDISABLE)
                try:
                    groups = ", ".join(win32net.NetUserGetLocalGroups(None, name))
                except Exception:
                    groups = "—"
                home = u.get('home_dir', '') or "—"
                row = self.existing_table.rowCount()
                self.existing_table.insertRow(row)
                name_item = QtWidgets.QTableWidgetItem(
                    f"🔒 {name}" if is_disabled else name)
                if is_disabled:
                    name_item.setForeground(QtGui.QColor("#ff7b72"))
                    name_item.setToolTip("Account ZABLOKOWANE")
                self.existing_table.setItem(row, 0, name_item)
                self.existing_table.setItem(row, 1, QtWidgets.QTableWidgetItem(groups))
                self.existing_table.setItem(row, 2, QtWidgets.QTableWidgetItem(home))
        except Exception as e:
            self._log(f"Error pobierania kont: {e}", "#ff7b72")

    def _get_selected_account(self) -> str:
        rows = self.existing_table.selectedItems()
        if not rows:
            QtWidgets.QMessageBox.warning(self, "No selection", "Select an account from the list.")
            return ""
        name = self.existing_table.item(rows[0].row(), 0).text()
        return name.replace("🔒 ", "").strip()

    def _toggle_block_account(self):
        name = self._get_selected_account()
        if not name:
            return
        try:
            info = win32net.NetUserGetInfo(None, name, 1)
            flags = info.get('flags', 0)
            is_disabled = bool(flags & win32netcon.UF_ACCOUNTDISABLE)
            action = "Unlock" if is_disabled else "Lock"
            confirm = QtWidgets.QMessageBox.question(
                self, f"{action} konto",
                f"{action} konto: {name}?" +
                ("" if is_disabled else "\n\nThe user will not be able to log in."),
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
            if confirm != QtWidgets.QMessageBox.Yes:
                return
            if is_disabled:
                info['flags'] = flags & ~win32netcon.UF_ACCOUNTDISABLE
                win32net.NetUserSetInfo(None, name, 1, info)
                self._log(f"✅ Account unlocked: {name}", "#7ee787")
            else:
                info['flags'] = flags | win32netcon.UF_ACCOUNTDISABLE
                win32net.NetUserSetInfo(None, name, 1, info)
                self._log(f"🔒 Account locked: {name}", "#e3b341")
            self._refresh_existing_users()
        except Exception as e:
            self._log(f"Error zmiany stanu konta '{name}': {e}", "#ff7b72")

    def _change_password_dialog(self):
        name = self._get_selected_account()
        if not name:
            return

        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle(f"Change password — {name}")
        dlg.setMinimumWidth(420)
        dlg.setStyleSheet(DARK_STYLE)
        lay = QtWidgets.QVBoxLayout(dlg)
        lay.setSpacing(10)
        lay.addWidget(QtWidgets.QLabel(f"New password for account:  <b>{name}</b>"))

        pass_edit = QtWidgets.QLineEdit()
        pass_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        pass_edit.setPlaceholderText("New password...")
        lay.addWidget(pass_edit)

        btn_eye = QtWidgets.QPushButton("👁  Show password")
        btn_eye.setCheckable(True)
        btn_eye.toggled.connect(lambda c: pass_edit.setEchoMode(
            QtWidgets.QLineEdit.Normal if c else QtWidgets.QLineEdit.Password))
        lay.addWidget(btn_eye)

        cb_force = QtWidgets.QCheckBox("Force password change at next login")
        cb_force.setChecked(True)
        lay.addWidget(cb_force)

        btn_row2 = QtWidgets.QHBoxLayout()
        btn_ok2 = QtWidgets.QPushButton("✅ Change Password")
        btn_ok2.setObjectName("btnGreen")
        btn_cancel2 = QtWidgets.QPushButton("Cancel")
        btn_ok2.clicked.connect(dlg.accept)
        btn_cancel2.clicked.connect(dlg.reject)
        btn_row2.addStretch()
        btn_row2.addWidget(btn_ok2)
        btn_row2.addWidget(btn_cancel2)
        lay.addLayout(btn_row2)

        if dlg.exec() != QtWidgets.QDialog.Accepted:
            return
        new_pass = pass_edit.text()
        force = cb_force.isChecked()
        if not new_pass:
            QtWidgets.QMessageBox.warning(self, "Error", "Password cannot be empty!")
            return
        try:
            win32net.NetUserSetInfo(None, name, 1003, {'password': new_pass})
        except Exception as e:
            self._log(f"Error changing password '{name}': {e}", "#ff7b72")
            QtWidgets.QMessageBox.critical(self, "Error", f"Cannot change password:\n{e}")
            return
        if force:
            try:
                info3 = win32net.NetUserGetInfo(None, name, 3)
                info3['password_expired'] = 1
                win32net.NetUserSetInfo(None, name, 3, info3)
            except Exception as e:
                self._log(f"Cannot set enforcement: {e}", "#e3b341")
        self._log(
            f"✅ Password changed for account: {name}"
            + (" (wymuszona zmiana przy logowaniu)" if force else ""), "#7ee787")
        QtWidgets.QMessageBox.information(
            self, "OK", f"Password for account '{name}' has been changed.")



    def _delete_account(self):
        name = self._get_selected_account()
        if not name:
            return
        confirm = QtWidgets.QMessageBox.warning(
            self, "Usun konto",
            f"Czy na pewno usunac konto: {name}? Operacja jest NIEODWRACALNA.",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No)
        if confirm != QtWidgets.QMessageBox.Yes:
            return
        try:
            win32net.NetUserDel(None, name)
            self._log(f"Usunieto konto: {name}", "#e3b341")
            self._refresh_existing_users()
            self._read_users_cd()
        except Exception as e:
            self._log(f"Blad usuwania konta '{name}': {e}", "#ff7b72")
            QtWidgets.QMessageBox.critical(self, "Blad", str(e))

    def _create_restore_point(self):
        desc = self.rp_desc.text().strip() or "Restore point — Pro Admin Tool"
        self.rp_status.setText("Tworzenie punktu przywracania...")
        self.rp_status.setStyleSheet("color: #e3b341; font-size: 12px; padding: 4px;")
        QtWidgets.QApplication.processEvents()
        try:
            ps_cmd = f'Checkpoint-Computer -Description "{desc}" -RestorePointType MODIFY_SETTINGS'
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                self.rp_status.setText(f"Punkt przywracania utworzony: {desc}")
                self.rp_status.setStyleSheet("color: #7ee787; font-size: 12px; padding: 4px;")
                self._log(f"Punkt przywracania: {desc}", "#7ee787")
            else:
                err = result.stderr.strip() or result.stdout.strip()
                raise RuntimeError(err)
        except subprocess.TimeoutExpired:
            self.rp_status.setText("Przekroczono czas oczekiwania (120s).")
            self.rp_status.setStyleSheet("color: #e3b341; font-size: 12px; padding: 4px;")
        except Exception as e:
            self.rp_status.setText(f"Blad: {e}")
            self.rp_status.setStyleSheet("color: #ff7b72; font-size: 12px; padding: 4px;")
            self._log(f"Blad punktu przywracania: {e}", "#ff7b72")
            QtWidgets.QMessageBox.warning(
                self, "Blad tworzenia punktu przywracania",
                "No udalo sie utworzyc punktu przywracania. "
                "Upewnij sie ze ochrona systemu jest wlaczona: "
                "Panel sterowania > System > Ochrona systemu > Konfiguruj")

    def _launch_recovery_drive(self):
        confirm = QtWidgets.QMessageBox.warning(
            self, "Dysk odzyskiwania",
            "Kreator dysku odzyskiwania usunie WSZYSTKIE dane z wybranego dysku USB. "
            "Podlacz pendrive (min. 8 GB) i kliknij OK.",
            QtWidgets.QMessageBox.Ok | QtWidgets.QMessageBox.Cancel)
        if confirm != QtWidgets.QMessageBox.Ok:
            return
        try:
            subprocess.Popen(["RecoveryDrive.exe"])
            self._log("Uruchomiono kreator dysku odzyskiwania.", "#58a6ff")
        except Exception as e:
            self._log(f"Blad: {e}", "#ff7b72")
            QtWidgets.QMessageBox.critical(self, "Blad",
                f"No mozna uruchomic kreatora: {e}")

    def _run_tool(self, cmd: list):
        try:
            subprocess.Popen(cmd, shell=(len(cmd) == 1))
            self._log(f"Uruchomiono: {cmd[0]}", "#58a6ff")
        except Exception as e:
            self._log(f"Blad uruchamiania {cmd[0]}: {e}", "#ff7b72")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            " ".join(f'"{a}"' for a in sys.argv), None, 1)
        sys.exit(0)
    else:
        window = AdminTool()
        window.show()
        sys.exit(app.exec())
