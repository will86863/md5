#!/usr/bin/env python3
"""
Duplicate File Finder and Remover (Tkinter GUI)
改进版：
- 双击文件选择“保留文件”
- 未选择的重复组自动随机保留一个
"""

import os
import hashlib
import threading
import queue
import time
import random
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# 可选回收站
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
    except Exception:
        return None
    return h.hexdigest()


class ScannerThread(threading.Thread):
    def __init__(self, folder, out_queue):
        super().__init__(daemon=True)
        self.folder = folder
        self.out_queue = out_queue

    def run(self):
        files = []
        for root, _, filenames in os.walk(self.folder):
            for fn in filenames:
                path = os.path.join(root, fn)
                try:
                    size = os.path.getsize(path)
                except Exception:
                    continue
                files.append((path, size))

        size_groups = {}
        for p, s in files:
            size_groups.setdefault(s, []).append(p)

        candidates = [g for g in size_groups.values() if len(g) > 1]
        total = sum(len(g) for g in candidates)

        md5_map = {}
        done = 0
        for group in candidates:
            for p in group:
                md5 = md5_of_file(p)
                done += 1
                if md5:
                    md5_map.setdefault(md5, []).append(p)
                self.out_queue.put(("progress", (done, total)))

        duplicates = {k: v for k, v in md5_map.items() if len(v) > 1}
        self.out_queue.put(("done", duplicates))


class App:
    def __init__(self, root):
        self.root = root
        root.title("重复文件检测并删除器（双击选择保留）")
        root.geometry("1000x600")

        self.folder_var = tk.StringVar()
        self.status_var = tk.StringVar(value="就绪")
        self.use_trash_var = tk.BooleanVar(value=False)

        self.duplicates = {}
        self.group_keys = []
        self.keep_map = {}  # md5 -> keep path

        self.queue = queue.Queue()

        self.build_ui()
        self.root.after(200, self.process_queue)

    def build_ui(self):
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill=tk.X)

        ttk.Label(top, text="检测文件夹:").pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.folder_var, width=60).pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="浏览", command=self.browse).pack(side=tk.LEFT)
        ttk.Checkbutton(top, text="使用回收站", variable=self.use_trash_var).pack(side=tk.LEFT, padx=10)

        ctrl = ttk.Frame(self.root, padding=8)
        ctrl.pack(fill=tk.X)

        ttk.Button(ctrl, text="开始扫描", command=self.start_scan).pack(side=tk.LEFT)
        ttk.Button(ctrl, text="确认并删除", command=self.confirm_and_delete).pack(side=tk.RIGHT)

        mid = ttk.Frame(self.root, padding=8)
        mid.pack(fill=tk.BOTH, expand=True)

        # 左侧：重复组
        left = ttk.Frame(mid)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.tv = ttk.Treeview(left, columns=("g", "c"), show="headings")
        self.tv.heading("g", text="组号")
        self.tv.heading("c", text="文件数")
        self.tv.pack(fill=tk.BOTH, expand=True)
        self.tv.bind("<<TreeviewSelect>>", self.on_group_select)

        # 右侧：文件列表
        right = ttk.Frame(mid)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)

        ttk.Label(right, text="双击文件 → 设为保留").pack(anchor=tk.W)

        self.file_listbox = tk.Listbox(right, selectmode=tk.SINGLE)
        self.file_listbox.pack(fill=tk.BOTH, expand=True)
        self.file_listbox.bind("<Double-Button-1>", self.on_file_double_click)

        bottom = ttk.Frame(self.root, padding=8)
        bottom.pack(fill=tk.X)

        ttk.Label(bottom, textvariable=self.status_var).pack(side=tk.LEFT)
        self.progress = ttk.Progressbar(bottom, length=300)
        self.progress.pack(side=tk.RIGHT)

    def browse(self):
        d = filedialog.askdirectory()
        if d:
            self.folder_var.set(d)

    def start_scan(self):
        folder = self.folder_var.get()
        if not os.path.isdir(folder):
            messagebox.showerror("错误", "请选择有效的文件夹")
            return

        self.duplicates.clear()
        self.keep_map.clear()
        self.group_keys.clear()
        self.tv.delete(*self.tv.get_children())
        self.file_listbox.delete(0, tk.END)

        self.status_var.set("扫描中...")
        self.progress["value"] = 0

        ScannerThread(folder, self.queue).start()

    def process_queue(self):
        try:
            while True:
                typ, payload = self.queue.get_nowait()
                if typ == "progress":
                    d, t = payload
                    if t:
                        self.progress["value"] = int(d * 100 / t)
                elif typ == "done":
                    self.duplicates = payload
                    self.group_keys = list(payload.keys())
                    for i, md5 in enumerate(self.group_keys, 1):
                        self.tv.insert("", "end", iid=str(i - 1), values=(i, len(payload[md5])))
                    self.status_var.set("扫描完成")
        except queue.Empty:
            pass

        self.root.after(200, self.process_queue)

    def on_group_select(self, event):
        sel = self.tv.selection()
        self.file_listbox.delete(0, tk.END)
        if not sel:
            return

        md5 = self.group_keys[int(sel[0])]
        for i, p in enumerate(self.duplicates[md5]):
            self.file_listbox.insert(tk.END, p)
            if self.keep_map.get(md5) == p:
                self.file_listbox.selection_set(i)

    def on_file_double_click(self, event):
        sel_group = self.tv.selection()
        sel_file = self.file_listbox.curselection()
        if not sel_group or not sel_file:
            return

        md5 = self.group_keys[int(sel_group[0])]
        keep_path = self.file_listbox.get(sel_file[0])
        self.keep_map[md5] = keep_path
        self.status_var.set("已选择保留文件")

    def confirm_and_delete(self):
        # 自动补全未选择的组（随机）
        for md5, paths in self.duplicates.items():
            if md5 not in self.keep_map:
                self.keep_map[md5] = random.choice(paths)

        deleted = 0
        for md5, paths in self.duplicates.items():
            keep = self.keep_map[md5]
            for p in paths:
                if p != keep:
                    try:
                        if self.use_trash_var.get() and CAN_TRASH:
                            send2trash(p)
                        else:
                            os.remove(p)
                        deleted += 1
                    except Exception as e:
                        print("删除失败:", p, e)

        messagebox.showinfo("完成", f"已删除 {deleted} 个重复文件")


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
