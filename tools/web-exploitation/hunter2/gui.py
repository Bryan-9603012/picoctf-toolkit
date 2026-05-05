import os
import sys
import threading
import io
import contextlib
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText


def resource_path(relative_path: str) -> str:
    base_path = getattr(sys, "_MEIPASS", os.path.abspath(os.path.dirname(__file__)))
    return os.path.join(base_path, relative_path)


APP_DIR = os.path.abspath(os.path.dirname(sys.executable if getattr(sys, "frozen", False) else __file__))

RULES_DIR = resource_path("rules")
PAYLOAD_DIR = resource_path("payloads")
FINGERPRINTS_DIR = resource_path("fingerprints")

REPORT_MD = os.path.join(APP_DIR, "report.md")
REPORT_JSON = os.path.join(APP_DIR, "report.json")


ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
REPORT_MD = os.path.join(ROOT_DIR, "report.md")
REPORT_JSON = os.path.join(ROOT_DIR, "report.json")


class HunterGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Hunter Scanner")
        self.root.geometry("860x620")
        self.root.minsize(760, 520)

        self.scanning = False

        self.target_var = tk.StringVar()
        self.mode_var = tk.StringVar(value="web")
        self.crawl_var = tk.BooleanVar(value=True)
        self.discover_var = tk.BooleanVar(value=True)
        self.passive_var = tk.BooleanVar(value=True)
        self.verbose_var = tk.BooleanVar(value=True)

        self._build_ui()

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill="both", expand=True)

        title = ttk.Label(main, text="Hunter Scanner", font=("Segoe UI", 16, "bold"))
        title.pack(anchor="w", pady=(0, 10))

        form = ttk.LabelFrame(main, text="Scan Settings", padding=10)
        form.pack(fill="x")

        ttk.Label(form, text="Target URL:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=6)
        target_entry = ttk.Entry(form, textvariable=self.target_var, width=72)
        target_entry.grid(row=0, column=1, columnspan=4, sticky="ew", pady=6)
        target_entry.focus()

        ttk.Label(form, text="Mode:").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=6)
        mode_box = ttk.Combobox(
            form,
            textvariable=self.mode_var,
            values=["ctf", "web", "stealth"],
            state="readonly",
            width=12,
        )
        mode_box.grid(row=1, column=1, sticky="w", pady=6)

        ttk.Checkbutton(form, text="Discover", variable=self.discover_var).grid(row=1, column=2, sticky="w", padx=10)
        ttk.Checkbutton(form, text="Crawl", variable=self.crawl_var).grid(row=1, column=3, sticky="w", padx=10)
        ttk.Checkbutton(form, text="Passive", variable=self.passive_var).grid(row=1, column=4, sticky="w", padx=10)
        ttk.Checkbutton(form, text="Verbose", variable=self.verbose_var).grid(row=1, column=5, sticky="w", padx=10)

        for i in range(6):
            form.columnconfigure(i, weight=1 if i == 1 else 0)

        btns = ttk.Frame(main)
        btns.pack(fill="x", pady=12)

        self.scan_btn = ttk.Button(btns, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side="left")

        self.stop_btn = ttk.Button(btns, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=8)

        ttk.Button(btns, text="Open report.md", command=lambda: self.open_file(REPORT_MD)).pack(side="left", padx=8)
        ttk.Button(btns, text="Open report.json", command=lambda: self.open_file(REPORT_JSON)).pack(side="left")

        self.status_var = tk.StringVar(value="Ready.")
        status = ttk.Label(main, textvariable=self.status_var)
        status.pack(anchor="w", pady=(0, 8))

        output_frame = ttk.LabelFrame(main, text="Output", padding=8)
        output_frame.pack(fill="both", expand=True)

        self.output = ScrolledText(output_frame, wrap="word", font=("Consolas", 10))
        self.output.pack(fill="both", expand=True)

    def append_output(self, text: str):
        self.output.insert("end", text)
        self.output.see("end")

    def set_status(self, text: str):
        self.status_var.set(text)

    def normalize_target(self, target: str) -> str:
        target = target.strip()
        if not target:
            return target
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        return target

    def build_args(self, target: str) -> list[str]:
        target = self.normalize_target(target)

        args = [
            target,
            "--mode", self.mode_var.get(),
            "--rules-dir", RULES_DIR,
            "--payload-dir", PAYLOAD_DIR,
            "--report", os.path.join(APP_DIR, "report"),
            "--outdir", os.path.join(APP_DIR, "loot"),
        ]

        if self.discover_var.get():
            args.append("--discover")
        if self.crawl_var.get():
            args.append("--crawl")
        if self.passive_var.get():
            args.append("--passive")
        if self.verbose_var.get():
            args.append("--verbose")

        return args

    def start_scan(self):
        if self.scanning:
            return

        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Missing Target", "Please enter a target URL.")
            return

        self.output.delete("1.0", "end")
        self.scanning = True
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.set_status("Scanning...")

        thread = threading.Thread(target=self.run_scan, daemon=True)
        thread.start()

    def run_scan(self):
        args = self.build_args(self.target_var.get().strip())

        self.root.after(0, lambda: self.append_output(f"$ hunter {' '.join(args)}\n\n"))

        buf = io.StringIO()

        try:
            from hunter import cli as hunter_cli

            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                old_argv = sys.argv[:]
                try:
                    sys.argv = ["hunter"] + args
                    rc = hunter_cli.main()
                finally:
                    sys.argv = old_argv

            output_text = buf.getvalue()
            self.root.after(0, lambda: self.append_output(output_text))

            if rc == 0:
                self.root.after(0, lambda: self.set_status("Scan finished successfully."))
            else:
                self.root.after(0, lambda: self.set_status(f"Scan finished with exit code {rc}."))

        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 0
            output_text = buf.getvalue()
            self.root.after(0, lambda: self.append_output(output_text))
            self.root.after(0, lambda: self.set_status(f"Scan finished with exit code {code}."))
        except Exception as e:
            output_text = buf.getvalue()
            self.root.after(0, lambda: self.append_output(output_text))
            self.root.after(0, lambda: self.append_output(f"\n[GUI ERROR] {e}\n"))
            self.root.after(0, lambda: self.set_status("Scan failed."))
        finally:
            self.scanning = False
            self.root.after(0, lambda: self.scan_btn.config(state="normal"))
            self.root.after(0, lambda: self.stop_btn.config(state="disabled"))

    def stop_scan(self):
        # 這版是直接呼叫 CLI main()，不是 subprocess，所以先不做強制中止
        self.append_output("\n[INFO] Stop is not supported in embedded mode yet.\n")
        self.set_status("Stop not supported in this mode.")

    def open_file(self, path: str):
        if not os.path.exists(path):
            messagebox.showinfo("Not Found", f"File not found:\n{path}")
            return

        try:
            os.startfile(path)
        except Exception as e:
            messagebox.showerror("Open Failed", f"Could not open file:\n{e}")


def main():
    root = tk.Tk()
    style = ttk.Style()
    try:
        style.theme_use("vista")
    except tk.TclError:
        pass

    HunterGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()