#!/usr/bin/env python3
"""
Duplicate File Finder and Remover (Tkinter GUI)

新增功能：
- 在重复文件组中【手动选择要保留的文件】
  - 右侧文件列表中【双击文件】即可设为“保留”
  - 删除时优先按用户选择，其次才随机保留
"""
import os
import hashlib
import threading
import queue
import random
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from send2trash import send2trash
    CAN_TRASH = True
except Exception:
    CAN_TRASH = False

CHUNK_SIZE = 8192


def md5_of_file(path):
    h = hashlib.md5()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                h.update(chunk)
    except Exception as e:
        return None, str(e)
    return h.hexdigest(), None


class ScannerThread(threading.Thread):
    def __init__(self, folder, out_queue, pause_event, stop_event):
        super().__init__(daemon=True)
        self.folder = folder
        self.out_queue = out_queue
        self.pause_event = pause_event
        self.stop_event = stop_event

    def run(self):
        files = []
        for root, _, filenames in os.walk(self.folder):
            for fn in filenames:
                if self.stop_event.is_set():
                    self.out_queue.put(("stopped", None))
                    return
                full = os.path.join(root, fn)
                try:
                    size = os.path.getsize(full)
                except Exception:
                    continue
                files.append((full, size))
                while self.pause_event.is_set() and not self.stop_event.is_set():
                    time.sleep(0.2)

        size_groups = {}
        for path, size in files:
            size_groups.setdefault(size, []).append(path)
        candidates = [g for g in size_groups.values() if len(g) > 1]

        md5_map = {}
        total = sum(len(g) for g in candidates)
        done = 0

        for group in candidates:
            for path in group:
                while self.pause_event.is_set() and not self.stop_event.is_set():
                    time.sleep(0.2)
                md5, err = md5_of_file(path)
                done += 1
                if not err:
                    md5_map.setdefault(md5, []).append(path)
                self.out_queue.put(("progress", (done, total)))

        duplicates = {m: p for m, p in md5_map.items() if len(p) > 1}
        self.out_queue.put(("done", duplicates))


class App:
    def __init__(self, root):
        self.root = root
        root.title("重复文件检测并删除器")
        root.geometry("900x600")

        self.folder_var = tk.StringVar()
        self.status_var = tk.StringVar(value="就绪")
        self.use_trash_var = tk.BooleanVar(value=False)

        self.manual_keep = {}  # md5 -> 用户选择保留的文件

        top = ttk.Frame(root, padding=8)
        top.pack(fill=tk.X)
        ttk.Label(top, text="文件夹:").pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.folder_var, width=60).pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="浏览", command=self.browse).pack(side=tk.LEFT)

        ctrl = ttk.Frame(root, padding=8)
        ctrl.pack(fill=tk.X)
        ttk.Button(ctrl, text="开始检测", command=self.start_scan).pack(side=tk.LEFT)
        self.confirm_btn = ttk.Button(ctrl, text="确认并删除", command=self.confirm_and_delete, state=tk.DISABLED)
        self.confirm_btn.pack(side=tk.RIGHT)

        mid = ttk.Frame(root, padding=8)
        mid.pack(fill=tk.BOTH, expand=True)

        self.tv = ttk.Treeview(mid, columns=("g", "c"), show="headings")
        self.tv.heading("g", text="组")
        self.tv.heading("c", text="文件数")
        self.tv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tv.bind("<<TreeviewSelect>>", self.on_group_select)

        self.file_listbox = tk.Listbox(mid)
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.file_listbox.bind("<Double-Button-1>", self.choose_keep_file)

        self.log_text = tk.Text(root, height=6)
        self.log_text.pack(fill=tk.BOTH)

        self.out_queue = queue.Queue()
        self.pause_event = threading.Event()
        self.stop_event = threading.Event()
        self.root.after(200, self.process_queue)

    def browse(self):
        d = filedialog.askdirectory()
        if d:
            self.folder_var.set(d)

    def log(self, msg):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def start_scan(self):
        self.manual_keep.clear()
        self.tv.delete(*self.tv.get_children())
        self.file_listbox.delete(0, tk.END)
        folder = self.folder_var.get()
        threading.Thread(
            target=ScannerThread(folder, self.out_queue, self.pause_event, self.stop_event).run,
            daemon=True
        ).start()

    def process_queue(self):
        try:
            while True:
                t, p = self.out_queue.get_nowait()
                if t == "done":
                    self.duplicates = p
                    for i, (md5, paths) in enumerate(p.items()):
                        self.tv.insert('', 'end', iid=str(i), values=(i + 1, len(paths)))
                    if p:
                        self.confirm_btn.config(state=tk.NORMAL)
        except queue.Empty:
            pass
        self.root.after(200, self.process_queue)

    def on_group_select(self, _):
        self.file_listbox.delete(0, tk.END)
        sel = self.tv.selection()
        if not sel:
            return
        md5 = list(self.duplicates.keys())[int(sel[0])]
        for p in self.duplicates[md5]:
            mark = " ★" if self.manual_keep.get(md5) == p else ""
            self.file_listbox.insert(tk.END, p + mark)

    def choose_keep_file(self, _):
        sel = self.file_listbox.curselection()
        grp = self.tv.selection()
        if not sel or not grp:
            return
        idx = int(grp[0])
        md5 = list(self.duplicates.keys())[idx]
        file_path = self.file_listbox.get(sel[0]).replace(" ★", "")
        self.manual_keep[md5] = file_path
        messagebox.showinfo("已选择", f"该组将保留:
{file_path}")
        self.on_group_select(None)

    def confirm_and_delete(self):
        for md5, paths in self.duplicates.items():
            keep = self.manual_keep.get(md5, random.choice(paths))
            for p in paths:
                if p != keep:
                    try:
                        os.remove(p)
                        self.log(f"删除: {p}")
                    except Exception as e:
                        self.log(f"失败: {p} {e}")
        messagebox.showinfo("完成", "重复文件已处理完成")


if __name__ == '__main__':
    tk.Tk().after(0, lambda: App(tk._default_root))
    tk.mainloop()
