#!/usr/bin/env python3
"""
Duplicate File Finder and Remover (Tkinter GUI)

Features:
- Choose a folder to scan (recursive)
- Start / Pause / Stop scanning
- Lists duplicate groups (files with identical MD5)
- After scan completes, shows duplicates and lets user confirm deletion
- On confirmation, in each duplicate group randomly keeps one file and deletes others
- Optionally use Recycle Bin (requires `send2trash` package)

Usage: python duplicate_file_cleaner.py

"""
import os
import hashlib
import threading
import queue
import random
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from functools import partial

# Try to import send2trash for safe deletion
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
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
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
        # 1. walk directory and collect files (skip directories)
        files = []
        for root, dirs, filenames in os.walk(self.folder):
            for fn in filenames:
                if self.stop_event.is_set():
                    self.out_queue.put(("stopped", None))
                    return
                full = os.path.join(root, fn)
                try:
                    size = os.path.getsize(full)
                except Exception as e:
                    self.out_queue.put(("log", f"无法读取文件大小: {full} ({e})"))
                    continue
                files.append((full, size))
                # respect pause
                while self.pause_event.is_set() and not self.stop_event.is_set():
                    time.sleep(0.2)
        self.out_queue.put(("log", f"扫描到 {len(files)} 个文件，按文件大小分组..."))

        # 2. group by size
        size_groups = {}
        for path, size in files:
            size_groups.setdefault(size, []).append(path)
        candidates = [lst for lst in size_groups.values() if len(lst) > 1]
        total_candidate_files = sum(len(lst) for lst in candidates)
        self.out_queue.put(("log", f"发现 {len(candidates)} 个大小相同的组，共 {total_candidate_files} 个候选文件"))

        # 3. for each candidate compute md5 (pause-respect)
        md5_map = {}  # md5 -> list of paths
        processed = 0
        for group in candidates:
            if self.stop_event.is_set():
                self.out_queue.put(("stopped", None))
                return
            for path in group:
                while self.pause_event.is_set() and not self.stop_event.is_set():
                    time.sleep(0.2)
                md5, err = md5_of_file(path)
                processed += 1
                if err:
                    self.out_queue.put(("log", f"无法读取文件: {path} ({err})"))
                    continue
                md5_map.setdefault(md5, []).append(path)
                self.out_queue.put(("progress", (processed, total_candidate_files)))

        # 4. filter md5 groups with more than 1 file -> duplicates
        duplicates = {md5: paths for md5, paths in md5_map.items() if len(paths) > 1}
        self.out_queue.put(("done", duplicates))


class App:
    def __init__(self, root):
        self.root = root
        root.title("重复文件检测并删除器")
        root.geometry("900x600")

        self.folder_var = tk.StringVar()
        self.status_var = tk.StringVar(value="就绪")
        self.use_trash_var = tk.BooleanVar(value=False)

        top = ttk.Frame(root, padding=8)
        top.pack(fill=tk.X)

        ttk.Label(top, text="要检测的文件夹:").pack(side=tk.LEFT)
        self.entry = ttk.Entry(top, textvariable=self.folder_var, width=60)
        self.entry.pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="浏览", command=self.browse).pack(side=tk.LEFT)
        ttk.Checkbutton(top, text="使用回收站(需要 send2trash)", variable=self.use_trash_var).pack(side=tk.LEFT, padx=10)

        ctrl = ttk.Frame(root, padding=8)
        ctrl.pack(fill=tk.X)
        self.start_btn = ttk.Button(ctrl, text="开始检测", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT)
        self.pause_btn = ttk.Button(ctrl, text="暂停", command=self.toggle_pause, state=tk.DISABLED)
        self.pause_btn.pack(side=tk.LEFT, padx=6)
        self.stop_btn = ttk.Button(ctrl, text="停止", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)
        self.confirm_btn = ttk.Button(ctrl, text="确认并删除重复文件", command=self.confirm_and_delete, state=tk.DISABLED)
        self.confirm_btn.pack(side=tk.RIGHT)

        mid = ttk.Frame(root, padding=8)
        mid.pack(fill=tk.BOTH, expand=True)

        # Left: Treeview for duplicate groups
        left = ttk.Frame(mid)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ttk.Label(left, text="检测到的重复组 (MD5 -> 文件列表):").pack(anchor=tk.W)
        columns = ("group", "count")
        self.tv = ttk.Treeview(left, columns=columns, show="headings")
        self.tv.heading("group", text="组号")
        self.tv.heading("count", text="文件数")
        self.tv.pack(fill=tk.BOTH, expand=True)
        self.tv.bind("<<TreeviewSelect>>", self.on_group_select)

        # Right: Listbox for files in selected group
        right = ttk.Frame(mid)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ttk.Label(right, text="选中组的文件(右侧预览):").pack(anchor=tk.W)
        self.file_listbox = tk.Listbox(right)
        self.file_listbox.pack(fill=tk.BOTH, expand=True)

        # Bottom: log and status
        bottom = ttk.Frame(root, padding=8)
        bottom.pack(fill=tk.X)
        ttk.Label(bottom, textvariable=self.status_var).pack(side=tk.LEFT)
        self.progress = ttk.Progressbar(bottom, orient=tk.HORIZONTAL, length=300)
        self.progress.pack(side=tk.RIGHT)

        logf = ttk.Frame(root, padding=8)
        logf.pack(fill=tk.BOTH)
        ttk.Label(logf, text="日志:").pack(anchor=tk.W)
        self.log_text = tk.Text(logf, height=8)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # internal
        self.scan_thread = None
        self.out_queue = queue.Queue()
        self.pause_event = threading.Event()  # when set -> paused
        self.stop_event = threading.Event()
        self.duplicates = {}  # md5 -> [paths]
        self.group_keys = []

        # start UI poll
        self.root.after(200, self.process_queue)

    def browse(self):
        d = filedialog.askdirectory()
        if d:
            self.folder_var.set(d)

    def log(self, msg):
        ts = time.strftime('%Y-%m-%d %H:%M:%S')
        self.log_text.insert(tk.END, f"[{ts}] {msg}\n")
        self.log_text.see(tk.END)

    def start_scan(self):
        folder = self.folder_var.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showerror("错误", "请选择有效的文件夹路径。")
            return
        # disable/enable buttons
        self.start_btn.config(state=tk.DISABLED)
        self.pause_btn.config(state=tk.NORMAL, text="暂停")
        self.stop_btn.config(state=tk.NORMAL)
        self.confirm_btn.config(state=tk.DISABLED)
        self.status_var.set("扫描中...")
        self.progress['value'] = 0
        self.log(f"开始扫描: {folder}")

        # reset
        self.duplicates = {}
        for i in self.tv.get_children():
            self.tv.delete(i)
        self.file_listbox.delete(0, tk.END)

        # reset events
        self.pause_event.clear()
        self.stop_event.clear()

        # start thread
        self.scan_thread = ScannerThread(folder, self.out_queue, self.pause_event, self.stop_event)
        self.scan_thread.start()

    def toggle_pause(self):
        if self.pause_event.is_set():
            # resume
            self.pause_event.clear()
            self.pause_btn.config(text="暂停")
            self.status_var.set("扫描中...")
            self.log("恢复扫描")
        else:
            self.pause_event.set()
            self.pause_btn.config(text="继续")
            self.status_var.set("已暂停")
            self.log("已暂停扫描")

    def stop_scan(self):
        if messagebox.askyesno("确认", "确定要停止当前扫描吗？" ):
            self.stop_event.set()
            self.pause_event.clear()
            self.start_btn.config(state=tk.NORMAL)
            self.pause_btn.config(state=tk.DISABLED, text="暂停")
            self.stop_btn.config(state=tk.DISABLED)
            self.status_var.set("已停止")
            self.log("用户已停止扫描")

    def process_queue(self):
        try:
            while True:
                typ, payload = self.out_queue.get_nowait()
                if typ == 'log':
                    self.log(payload)
                elif typ == 'progress':
                    done, total = payload
                    if total > 0:
                        val = int(done * 100 / total)
                        self.progress['value'] = val
                        self.status_var.set(f"计算MD5: {done}/{total}")
                elif typ == 'done':
                    self.duplicates = payload
                    self.on_scan_done()
                elif typ == 'stopped':
                    self.status_var.set("已停止")
                    self.log("扫描线程已停止")
                    self.start_btn.config(state=tk.NORMAL)
                    self.pause_btn.config(state=tk.DISABLED, text="暂停")
                    self.stop_btn.config(state=tk.DISABLED)
                else:
                    self.log(f"未识别消息: {typ} {payload}")
        except queue.Empty:
            pass
        finally:
            self.root.after(200, self.process_queue)

    def on_scan_done(self):
        self.log("扫描完成，准备显示重复组...")
        self.progress['value'] = 100
        self.status_var.set("扫描完成")
        # populate treeview
        self.tv.delete(*self.tv.get_children())
        self.group_keys = list(self.duplicates.keys())
        for i, md5 in enumerate(self.group_keys, start=1):
            paths = self.duplicates[md5]
            self.tv.insert('', 'end', iid=str(i-1), values=(i, len(paths)))
        if self.group_keys:
            self.confirm_btn.config(state=tk.NORMAL)
            self.log(f"共 {len(self.group_keys)} 个重复MD5组。")
        else:
            self.confirm_btn.config(state=tk.DISABLED)
            self.log("未发现重复文件。")
        # reset buttons
        self.start_btn.config(state=tk.NORMAL)
        self.pause_btn.config(state=tk.DISABLED, text="暂停")
        self.stop_btn.config(state=tk.DISABLED)

    def on_group_select(self, event):
        sel = self.tv.selection()
        self.file_listbox.delete(0, tk.END)
        if not sel:
            return
        idx = int(sel[0])
        md5 = self.group_keys[idx]
        for p in self.duplicates[md5]:
            self.file_listbox.insert(tk.END, p)

    def confirm_and_delete(self):
        if not self.duplicates:
            messagebox.showinfo("提示", "没有要删除的重复文件。")
            return
        # count how many files would be deleted
        total_delete = sum(len(paths)-1 for paths in self.duplicates.values())
        if total_delete <= 0:
            messagebox.showinfo("提示", "没有要删除的重复文件。")
            return
        msg = f"检测完成：将删除 {total_delete} 个重复文件（每组随机保留 1 个）。\n\n是否继续？"
        if not messagebox.askyesno("确认删除", msg):
            return
        # perform deletion
        self.log(f"用户确认删除 {total_delete} 个文件，开始执行删除...")
        deleted = 0
        failed = []
        for md5, paths in self.duplicates.items():
            # choose one randomly to keep
            keep = random.choice(paths)
            for p in paths:
                if p == keep:
                    continue
                try:
                    if self.use_trash_var.get() and CAN_TRASH:
                        send2trash(p)
                    else:
                        os.remove(p)
                    deleted += 1
                    self.log(f"已删除: {p}")
                except Exception as e:
                    self.log(f"删除失败: {p} ({e})")
                    failed.append((p, str(e)))
        self.log(f"删除完成。已删除 {deleted} 个，失败 {len(failed)} 个。")
        messagebox.showinfo("完成", f"已删除 {deleted} 个文件，失败 {len(failed)} 个。请查看日志以获取详细信息。")
        # after deletion, disable confirm
        self.confirm_btn.config(state=tk.DISABLED)


if __name__ == '__main__':
    root = tk.Tk()
    app = App(root)
    if not CAN_TRASH:
        app.log("提示: 未检测到 send2trash 库。启用回收站功能需先 `pip install send2trash`。")
    root.mainloop()
