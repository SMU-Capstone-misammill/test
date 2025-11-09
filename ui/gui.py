# ui/gui.py  — Modern UI (Dark-ready, Tray, Badges, Cards) + 분석 범위 설정 기능 추가
import json
import os
import sys
import traceback
import csv  # ✅ (추가) CSV 내보내기
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, QThreadPool, QRunnable, Signal, QObject, QSize
from PySide6.QtGui import QAction, QIcon, QColor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem,
    QLabel, QHeaderView, QStatusBar, QAbstractItemView, QFrame, QToolBar,
    QSystemTrayIcon, QMenu, QStyle, QLineEdit  # ✅ (추가) QLineEdit
)

# -----------------------------
# Project paths
# -----------------------------
ROOT = Path(__file__).resolve().parents[1]
LOGS_DIR = ROOT / "logs"
DETECTIONS_JSON = LOGS_DIR / "detections.json"
QUARANTINE_DIR = ROOT / "quarantine"

# 🔧 (추가) 설정 파일 경로 및 기본 분석 범위
CONFIG_DIR = ROOT / "config"
SETTINGS_JSON = CONFIG_DIR / "settings.json"
DEFAULT_ALLOWED_ROOT = Path("C:/")  # 기본값: C 드라이브 전체

# -----------------------------
# Analyzer import (+ DEV stub)
# -----------------------------
ANALYZER_AVAILABLE = True
try:
    sys.path.append(str(ROOT))
    from core import analyzer  # analyzer.analyze_file(path[, base_dir=...]) 권장
except Exception as e:
    ANALYZER_AVAILABLE = False
    ANALYZER_IMPORT_ERROR = str(e)

DEV_MODE = os.environ.get("AISEC_DEV", "0") == "1"
if not ANALYZER_AVAILABLE and DEV_MODE:
    class _DummyAnalyzer:
        @staticmethod
        def analyze_file(path: str, base_dir: str | None = None):
            import random
            conf = round(random.uniform(0.6, 0.99), 3)
            result = "악성" if conf > 0.85 else "정상"
            return {
                "file": path,
                "result": result,
                "confidence": conf,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
    analyzer = _DummyAnalyzer()
    ANALYZER_AVAILABLE = True


# -----------------------------
# IO helpers
# -----------------------------
def ensure_paths():
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    if not DETECTIONS_JSON.exists():
        with open(DETECTIONS_JSON, "w", encoding="utf-8") as f:
            json.dump([], f, ensure_ascii=False, indent=2)

# (추가) 설정 로드/저장
def load_settings():
    try:
        with open(SETTINGS_JSON, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_settings(obj: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(SETTINGS_JSON, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def load_detections():
    try:
        with open(DETECTIONS_JSON, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def append_detection_safe(entry: dict):
    data = load_detections()
    data.append(entry)
    with open(DETECTIONS_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# -----------------------------
# Worker (non-blocking analyze)
# -----------------------------
class WorkerSignals(QObject):
    finished = Signal(object)


class AnalyzeWorker(QRunnable):
    def __init__(self, file_path: str, allowed_root: Path | None = None):
        super().__init__()
        self.file_path = file_path
        self.allowed_root = allowed_root  # (추가) analyzer에 base_dir 전달
        self.signals = WorkerSignals()

    def run(self):
        if not ANALYZER_AVAILABLE:
            self.signals.finished.emit({
                "ok": False,
                "error": f"analyzer 임포트 오류: {globals().get('ANALYZER_IMPORT_ERROR', '')}"
            })
            return
        try:
            # analyzer가 base_dir를 지원하면 함께 전달, 아니면 자동 폴백
            try:
                res = analyzer.analyze_file(self.file_path, base_dir=str(self.allowed_root) if self.allowed_root else None)
            except TypeError:
                res = analyzer.analyze_file(self.file_path)

            result = {
                "file": self.file_path,
                "result": res.get("result", "알수없음"),
                "confidence": float(res.get("confidence", 0.0)),
                "timestamp": res.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            }
            append_detection_safe(result)
            self.signals.finished.emit({"ok": True, "data": result})
        except Exception as e:
            self.signals.finished.emit({
                "ok": False,
                "error": f"{e}\n{traceback.format_exc()}"
            })


# -----------------------------
# Main Window (Modernized)
# -----------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        ensure_paths()

        # (추가) 설정 로드 및 분석 범위 초기화
        s = load_settings()
        allowed_root_str = s.get("allowed_root", str(DEFAULT_ALLOWED_ROOT))
        try:
            self.allowed_root = Path(allowed_root_str).resolve()
        except Exception:
            self.allowed_root = DEFAULT_ALLOWED_ROOT.resolve()

        self.setWindowTitle("AI Security Agent")
        self.resize(1000, 620)
        self.setWindowIcon(self._icon_shield())

        # Optional: apply dark theme if available
        self._apply_theme()

        # Top toolbar
        self._build_toolbar()

        # Header card
        header = self._build_header_card()

        # Action buttons card
        actions_card = self._build_actions_card()

        # Log table card
        self.table = self._build_table_card()

        # Layout (nice spacing)
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)
        root.addWidget(header)
        root.addWidget(actions_card)
        root.addWidget(self.table_frame)
        self.setCentralWidget(central)

        # Status bar
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self._set_status_badge("Auto refresh: 5s", good=True)

        # Thread pool + timer
        self.thread_pool = QThreadPool.globalInstance()
        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(5000)
        self.refresh_timer.timeout.connect(self.populate_table)
        self.refresh_timer.start()

        # (추가) 로그 원본 캐시 (검색/필터용)
        self._all_rows_cache = []

        # First load
        self.populate_table()

        # Analyzer warning
        if not ANALYZER_AVAILABLE:
            QMessageBox.warning(
                self, "Analyzer 로드 실패",
                f"core/analyzer.py 임포트에 실패했습니다.\n\n{globals().get('ANALYZER_IMPORT_ERROR','')}\n\n"
                "개발 모드로 테스트하려면:\nset AISEC_DEV=1 후 실행하세요."
            )

        # System Tray
        self._setup_tray()

        # App-wide style tweaks (rounded, subtle elevation)
        self._apply_qss()

        # ✅ (추가) 드래그&드롭 활성화
        self.setAcceptDrops(True)

    # ----- UI builders -----
    def _build_toolbar(self):
        tb = QToolBar("Main")
        tb.setIconSize(QSize(18, 18))
        tb.setMovable(False)

        act_analyze = QAction(self._icon_search(), "파일 분석하기", self)
        act_analyze.triggered.connect(self.on_click_analyze)

        act_refresh = QAction(self._icon_refresh(), "로그 새로고침", self)
        act_refresh.triggered.connect(self.populate_table)

        act_open_quar = QAction(self._icon_folder(), "격리 폴더 열기", self)
        act_open_quar.triggered.connect(lambda: self.open_in_explorer(QUARANTINE_DIR))

        act_open_logs = QAction(self._icon_folder(), "로그 폴더 열기", self)
        act_open_logs.triggered.connect(lambda: self.open_in_explorer(LOGS_DIR))

        act_about = QAction(self._icon_info(), "정보", self)
        act_about.triggered.connect(self.show_about)

        tb.addAction(act_analyze)
        tb.addAction(act_refresh)
        tb.addSeparator()
        tb.addAction(act_open_quar)
        tb.addAction(act_open_logs)
        tb.addSeparator()
        tb.addAction(act_about)
        self.addToolBar(tb)

    def _build_header_card(self):
        card = self._card()
        lay = QHBoxLayout(card)
        lay.setContentsMargins(16, 14, 16, 14)
        icon = QLabel()
        icon.setPixmap(self._icon_shield().pixmap(28, 28))
        title = QLabel("AI Security Agent")
        title.setStyleSheet("font-size: 20px; font-weight: 700;")

        # 설명 문구(심사용)
        subtitle = QLabel("AI가 수행한 보안 분석 결과를 확인하고 수동 검사를 진행할 수 있는 창입니다.")
        subtitle.setStyleSheet("color: palette(mid);")

        # (추가) 현재 분석 범위 표시
        self.lbl_scope = QLabel(f"분석 범위: {self.allowed_root}")
        self.lbl_scope.setStyleSheet("color: palette(mid); font-size: 12px;")

        text_box = QVBoxLayout()
        text_box.setSpacing(2)
        text_box.addWidget(title)
        text_box.addWidget(subtitle)
        text_box.addWidget(self.lbl_scope)

        lay.addWidget(icon)
        lay.addSpacing(8)
        lay.addLayout(text_box)
        lay.addStretch(1)
        self.header_frame = card
        return card

    def _build_actions_card(self):
        card = self._card()
        lay = QHBoxLayout(card)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(8)

        self.btn_analyze = self._pill_button("파일 분석하기", icon=self._icon_search())
        self.btn_analyze.clicked.connect(self.on_click_analyze)

        self.btn_refresh = self._pill_button("로그 새로고침", icon=self._icon_refresh())
        self.btn_refresh.clicked.connect(self.populate_table)

        self.btn_scope = self._pill_button("분석 경로 선택", icon=self._icon_folder())
        self.btn_scope.clicked.connect(self.change_scope)

        self.btn_quar = self._pill_button("격리 폴더 열기", icon=self._icon_folder())
        self.btn_quar.clicked.connect(lambda: self.open_in_explorer(QUARANTINE_DIR))

        self.btn_logs = self._pill_button("로그 폴더 열기", icon=self._icon_folder())
        self.btn_logs.clicked.connect(lambda: self.open_in_explorer(LOGS_DIR))

        # ✅ (추가) CSV 내보내기
        self.btn_export = self._pill_button("CSV 내보내기", icon=self._icon_info())
        self.btn_export.clicked.connect(self.export_csv)

        # ✅ (추가) 검색창
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("로그 검색 (파일/결과)")
        self.search_box.textChanged.connect(self.apply_filter)
        self.search_box.setFixedWidth(220)

        lay.addWidget(self.btn_analyze)
        lay.addWidget(self.btn_refresh)
        lay.addWidget(self.btn_scope)  # 추가
        lay.addStretch(1)
        lay.addWidget(self.btn_quar)
        lay.addWidget(self.btn_logs)
        lay.addWidget(self.btn_export)   # ✅ 추가
        lay.addSpacing(8)
        lay.addWidget(self.search_box)   # ✅ 추가
        self.actions_frame = card
        return card

    def _build_table_card(self):
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["시간", "파일 경로", "결과", "신뢰도"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("QTableWidget { background: transparent; }")

        card = self._card()
        lay = QVBoxLayout(card)
        lay.setContentsMargins(12, 12, 12, 12)
        title = QLabel("감지 로그")
        title.setStyleSheet("font-weight: 600;")
        hint = QLabel("최신 항목이 위에 표시됩니다")
        hint.setStyleSheet("color: palette(mid); font-size: 12px;")

        header_line = QHBoxLayout()
        header_line.addWidget(title)
        header_line.addStretch()
        header_line.addWidget(hint)

        lay.addLayout(header_line)
        lay.addWidget(self.table)

        # ✅ (추가) 행 더블클릭 → 파일 위치 열기
        self.table.itemDoubleClicked.connect(self.open_row_location)

        self.table_frame = card
        return self.table

    # ----- Actions -----
    def populate_table(self):
        data = load_detections()
        try:
            data.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        except Exception:
            pass

        # ✅ (추가) 원본 캐시 저장 및 표시
        self._all_rows_cache = data
        self._fill_table(data)

        # ✅ (추가) 마지막 갱신 시각 표기
        now = datetime.now().strftime("%H:%M:%S")
        self._set_status_badge(f"Auto refresh: 5s · 마지막 갱신 {now}", good=True)

    # ✅ (추가) 테이블 채우기 공통 함수
    def _fill_table(self, rows):
        self.table.setRowCount(0)
        for item in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)

            ts = item.get("timestamp", "")
            fp = item.get("file", "")
            res = item.get("result", "")
            conf = item.get("confidence", "")

            # 시간
            self.table.setItem(row, 0, QTableWidgetItem(str(ts)))
            # 파일
            item_fp = QTableWidgetItem(str(fp))
            item_fp.setToolTip(str(fp))
            self.table.setItem(row, 1, item_fp)
            # 결과 (badge-like)
            item_res = QTableWidgetItem(str(res))
            self.table.setItem(row, 2, item_res)
            self._style_result_cell(row, 2, str(res))
            # 신뢰도(퍼센트)
            self.table.setItem(row, 3, QTableWidgetItem(f"{float(conf)*100:.1f}%" if conf != "" else ""))

    def on_click_analyze(self):
        if not ANALYZER_AVAILABLE:
            QMessageBox.critical(self, "분석 불가", "analyzer가 로드되지 않아 분석을 실행할 수 없습니다.")
            return

        # 시작 디렉터리를 현재 허용 범위로
        files, _ = QFileDialog.getOpenFileNames(
            self, "분석할 파일 선택", str(self.allowed_root), "All Files (*.*)"
        )
        if not files:
            return

        paths = [Path(f).resolve() for f in files]
        self.analyze_many(paths)

    # ✅ (추가) 다중 파일 분석 공통 처리
    def analyze_many(self, paths: list[Path]):
        valid = []
        base = self.allowed_root.resolve()
        for fp in paths:
            try:
                inside = fp.is_relative_to(base)
            except AttributeError:
                inside = str(fp).lower().startswith(str(base).lower())
            if fp.is_file() and inside:
                valid.append(fp)

        if not valid:
            QMessageBox.warning(self, "분석 불가", "선택한 항목이 없거나 범위 밖입니다.")
            return

        self._set_status_badge("분석 중…", good=False)
        for fp in valid:
            worker = AnalyzeWorker(str(fp), allowed_root=self.allowed_root)  # base_dir 전달
            worker.signals.finished.connect(self.on_analyze_finished)
            self.thread_pool.start(worker)

    # (추가) 분석 범위 변경
    def change_scope(self):
        dir_path = QFileDialog.getExistingDirectory(self, "분석 범위(루트) 선택", str(self.allowed_root))
        if not dir_path:
            return
        p = Path(dir_path).resolve()

        # (선택) C: 하위만 허용하고 싶다면 아래 주석을 해제
        # if p.drive.upper() != "C:":
        #     QMessageBox.warning(self, "범위 제한", "현재 버전은 C: 드라이브 하위 폴더만 지정할 수 있습니다.")
        #     return

        self.allowed_root = p
        self.lbl_scope.setText(f"분석 범위: {self.allowed_root}")

        s = load_settings()
        s["allowed_root"] = str(self.allowed_root)
        save_settings(s)

        self.status.showMessage("분석 범위가 변경되었습니다.", 3000)

    def on_analyze_finished(self, payload: object):
        self._set_status_badge("Auto refresh: 5s", good=True)
        if not isinstance(payload, dict):
            QMessageBox.critical(self, "오류", "알 수 없는 분석 결과 포맷입니다.")
            return
        if not payload.get("ok"):
            QMessageBox.critical(self, "분석 실패", f"{payload.get('error')}")
            return

        d = payload["data"]
        # 신뢰도 퍼센트로 보기 좋게
        conf_pct = f"{float(d['confidence'])*100:.1f}%"

        # 메시지 텍스트
        text = (
            f"파일: {d['file']}\n"
            f"결과: {d['result']}\n"
            f"신뢰도: {conf_pct}\n"
            f"시간: {d['timestamp']}"
        )

        msg = QMessageBox(self)
        msg.setWindowTitle("분석 완료")
        msg.setText(text)

        if str(d['result']).strip() == "정상":
            icon = self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation)
            msg.setIconPixmap(icon.pixmap(48, 48))
        elif str(d['result']).strip() == "악성":
            msg.setIcon(QMessageBox.Icon.Critical)
        else:
            msg.setIcon(QMessageBox.Icon.Warning)

        msg.exec()
        self.populate_table()

    def open_in_explorer(self, path: Path):
        path.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(path))
        except Exception as e:
            QMessageBox.warning(self, "열기 실패", f"폴더를 열 수 없습니다.\n{e}")

    # ✅ (추가) 테이블 더블클릭 시 파일 위치 열기
    def open_row_location(self, item: QTableWidgetItem):
        r = item.row()
        fp = self.table.item(r, 1).text().strip()
        p = Path(fp)
        if p.exists():
            os.system(f'explorer /select,"{str(p)}"')
        else:
            QMessageBox.warning(self, "열기 실패", "파일을 찾을 수 없습니다.")

    # ✅ (추가) 검색/필터
    def apply_filter(self, text: str):
        t = (text or "").strip().lower()
        if not t:
            self._fill_table(self._all_rows_cache)
            return
        filt = []
        for d in self._all_rows_cache:
            s = f"{d.get('file','')} {d.get('result','')}".lower()
            if t in s:
                filt.append(d)
        self._fill_table(filt)

    # ✅ (추가) CSV 내보내기
    def export_csv(self):
        rows = self._all_rows_cache or []
        if not rows:
            QMessageBox.information(self, "CSV 내보내기", "내보낼 로그가 없습니다.")
            return
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        name = f"logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        out = LOGS_DIR / name
        with open(out, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["시간", "파일", "결과", "신뢰도(%)"])
            for d in rows:
                w.writerow([
                    d.get("timestamp", ""),
                    d.get("file", ""),
                    d.get("result", ""),
                    f"{float(d.get('confidence', 0.0))*100:.1f}"
                ])
        QMessageBox.information(self, "CSV 내보내기", f"저장됨: {out}")

    def show_about(self):
        QMessageBox.information(
            self, "정보",
            "AI Security Agent\n"
            "인공지능 기반 보안 분석 도구\n\n"
            "• 어두운 테마(다크모드) 지원\n"
            "• 직관적인 카드형 인터페이스\n"
            "• 악성·정상 결과를 색상으로 구분 표시\n"
            "• 시스템 트레이에서 백그라운드 실행 지원\n"
            "• 자동 로그 갱신 (5초 주기)"
        )

    # ----- Helpers -----
    def _apply_theme(self):
        # Try apply dark theme if qdarktheme installed
        try:
            import qdarktheme
            qdarktheme.setup_theme("dark")
        except Exception:
            pass  # fallback to default

    def _apply_qss(self):
        # Subtle, rounded, modern buttons/frames
        self.setStyleSheet(
            """
            * { font-family: 'Segoe UI', 'Malgun Gothic', sans-serif; }
            QMainWindow { background: palette(base); }
            QToolBar { border: none; padding: 6px; }
            QStatusBar { background: transparent; }

            /* Cards */
            QFrame#card {
                background: palette(alternate-base);
                border: 1px solid rgba(255,255,255,0.08);
                border-radius: 12px;
            }

            /* Pill buttons */
            QPushButton#pill {
                border: 1px solid rgba(255,255,255,0.14);
                border-radius: 18px;
                padding: 8px 14px;
            }
            QPushButton#pill:hover {
                border-color: rgba(100,180,255,0.65);
            }
            """
        )

    def _card(self) -> QFrame:
        f = QFrame()
        f.setObjectName("card")
        return f

    def _pill_button(self, text: str, icon: QIcon | None = None):
        b = QPushButton(text)
        if icon:
            b.setIcon(icon)
        b.setObjectName("pill")
        return b

    def _style_result_cell(self, row: int, col: int, result: str):
        item = self.table.item(row, col)
        if not item:
            return
        # Badge-like color
        if str(result).strip() == "악성":
            bg = QColor(200, 40, 40, 130)
            fg = QColor(255, 235, 235)
            label = "악성"
        elif str(result).strip() == "정상":
            bg = QColor(40, 160, 60, 120)
            fg = QColor(235, 255, 240)
            label = "정상"
        else:
            bg = QColor(140, 140, 160, 90)
            fg = QColor(245, 245, 255)
            label = str(result)

        item.setText(label)
        item.setForeground(fg)
        item.setBackground(bg)

    def _set_status_badge(self, text: str, good=True):
        color = "#3fb950" if good else "#d29922"
        self.status.showMessage(text)
        # Extra: set a colored dot at left by updating window title icon hint (skip for simplicity)

    # Icons (use standard if available)
    def _icon_shield(self):
        return QIcon.fromTheme("security-high") or QIcon.fromTheme("emblem-shared") or QIcon()

    def _icon_search(self):
        return QIcon.fromTheme("system-search") or QIcon.fromTheme("edit-find") or QIcon()

    def _icon_refresh(self):
        return QIcon.fromTheme("view-refresh") or QIcon()

    def _icon_folder(self):
        return QIcon.fromTheme("folder") or QIcon()

    def _icon_info(self):
        return QIcon.fromTheme("help-about") or QIcon()

    # System tray integration
    def _setup_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(self._icon_shield(), self)
        menu = QMenu()
        act_show = QAction("창 열기", self, triggered=self.show_normal_raise)
        act_quit = QAction("종료", self, triggered=QApplication.instance().quit)
        menu.addAction(act_show)
        menu.addSeparator()
        menu.addAction(act_quit)
        self.tray.setContextMenu(menu)
        self.tray.setToolTip("AI Security Agent")
        self.tray.show()

    def show_normal_raise(self):
        self.showNormal()
        self.activateWindow()

    def closeEvent(self, event):
        # Minimize to tray instead of closing
        if hasattr(self, "tray") and self.tray.isVisible():
            self.hide()
            self.tray.showMessage(
                "AI Security Agent",
                "창이 트레이로 최소화되었습니다.",
                QSystemTrayIcon.MessageIcon.Information, 2500
            )
            event.ignore()
        else:
            super().closeEvent(event)

    # ✅ (추가) 드래그&드롭 핸들러
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        paths = [Path(u.toLocalFile()).resolve() for u in e.mimeData().urls()]
        self.analyze_many(paths)


# -----------------------------
# Entry
# -----------------------------
def main():
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")
    os.environ.setdefault("QT_SCALE_FACTOR", "1")
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
