"""
Lab Mode consent dialog.

Shown the first time (per session) that the user starts a scan with Lab
Mode enabled. Requires two explicit checkbox acknowledgments before the
OK button becomes active.

We don't persist consent across sessions on purpose — this is a teaching
moment every time.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QCheckBox, QDialogButtonBox,
)


CONSENT_TEXT = (
    "<h3 style='color:#b45309'>You are about to enable Lab Mode.</h3>"
    "<p>Lab Mode performs <b>active</b> checks against discovered devices, "
    "including attempting to log in with a small list of well-known default "
    "credentials on FTP, Telnet, SSH, and HTTP admin panels.</p>"
    "<p>These checks can:</p>"
    "<ul>"
    "<li>trigger intrusion-detection systems,</li>"
    "<li>lock user accounts on devices with failed-login thresholds,</li>"
    "<li>violate terms of service or local law if run against networks or "
    "devices you do not own or are not authorized to test.</li>"
    "</ul>"
    "<p>By enabling Lab Mode you confirm you have <b>written authorization "
    "or ownership</b> of every device on the target subnet.</p>"
)


class LabConsentDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Lab Mode — Authorization required")
        self.setModal(True)
        self.resize(540, 420)

        lay = QVBoxLayout(self)

        body = QLabel(CONSENT_TEXT)
        body.setWordWrap(True)
        body.setTextFormat(Qt.TextFormat.RichText)
        lay.addWidget(body)

        self.cb_authorized = QCheckBox(
            "I own or have written authorization for every device on the target network."
        )
        self.cb_responsible = QCheckBox(
            "I accept responsibility for any impact these active checks may cause."
        )
        self.cb_authorized.stateChanged.connect(self._refresh)
        self.cb_responsible.stateChanged.connect(self._refresh)
        lay.addWidget(self.cb_authorized)
        lay.addWidget(self.cb_responsible)

        self.btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        self.btns.accepted.connect(self.accept)
        self.btns.rejected.connect(self.reject)
        self._ok = self.btns.button(QDialogButtonBox.StandardButton.Ok)
        self._ok.setText("Enable Lab Mode")
        lay.addWidget(self.btns)

        self._refresh()

    def _refresh(self) -> None:
        self._ok.setEnabled(self.cb_authorized.isChecked()
                            and self.cb_responsible.isChecked())
