import hashlib
import zlib
import os
import re
import sys
import time
import functools
import platform
import hash_check_qrc
from PyQt5 import QtGui, QtCore, QtWidgets, uic

__version__ = "0.4.1"

# Windows7 Taskbar Grouping (Don't group with Python)
if platform.system() == 'Windows' and platform.release() == '7':
    import ctypes
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('Checksum_Calculator')

class CRC32(object):
    name = 'crc32'
    digest_size = 4
    block_size = 64

    def __init__(self, arg=''):
        self.__hash = 0

    def copy(self):
        return self

    def digest(self):
        return self.__hash & 0xffffffff

    def hexdigest(self):
        return '%08X' % (self.digest())

    def update(self, arg):
        self.__hash = zlib.crc32(arg, self.__hash)

# Now you can define hashlib.crc32 = CRC32
hashlib.crc32 = CRC32

# Python 2.7: hashlib.algorithms += ('crc32',)
hashlib.algorithms_available.add('crc32')

algo_length_dict = {
	8:"CRC32",
	32:"MD5",
	40:"SHA1",
	56:"SHA224",
	64:"SHA265",
	96:"SHA384",
	128:"SHA512"
}

class GenericThread(QtCore.QThread):
	def __init__(self, function, *args, **kwargs):
		QtCore.QThread.__init__(self)
		self.function = function
		self.args = args
		self.kwargs = kwargs
 
	def __del__(self):
		self.wait()
 
	def run(self):
		self.function(*self.args,**self.kwargs)
		return

class Checksum_Calculator(QtWidgets.QMainWindow):

	signal_update_progessbar = QtCore.pyqtSignal(int)
	signal_treeview_add_new_file = QtCore.pyqtSignal(str, str, str, str)

	def __init__(self):
		QtWidgets.QMainWindow.__init__(self)
		
		self.ui = uic.loadUi('hash_check.ui', self)
		
		self.ui.toolBar.addWidget(self.ui.labelAlgorithm)
		self.ui.toolBar.addWidget(self.ui.comboBox)
		
		icon = QtGui.QIcon()
		icon.addFile(':/window/ico16', QtCore.QSize(16, 16))
		icon.addFile(':/window/ico24', QtCore.QSize(24, 24))
		icon.addFile(':/window/ico32', QtCore.QSize(32, 32))
		icon.addFile(':/window/ico48', QtCore.QSize(48, 48))
		icon.addFile(':/window/ico64', QtCore.QSize(64, 64))
		self.ui.setWindowIcon(icon)
		
		self.icons = {}
		self.icons["logo"] = icon
		self.icons["blank"] = QtGui.QIcon()
		self.icons["accept"] = QtGui.QIcon(":/list/accept")
		self.icons["error"] = QtGui.QIcon(":/list/error")
		self.icons["exclamation"] = QtGui.QIcon(":/list/exclamation")
		self.icons["question"] = QtGui.QIcon(":/list/question")
		
		
		self.algo_dict = {}
		algos = set()
		for algo in hashlib.algorithms_available:
			algos.add(algo.upper())
			self.algo_dict[algo.upper()] = algo
		algos = list(algos)
		algos.sort()
		self.ui.comboBox.clear()
		for algo in algos:
			self.ui.comboBox.addItem(algo)
		self.ui.treeWidget.setAcceptDrops(True)
		self.ui.treeWidget.dragEnterEvent = self.dragEnterEvent
		self.ui.treeWidget.dragMoveEvent = self.dragMoveEvent
		self.ui.treeWidget.dropEvent = self.dropEvent
		self.show()
		
		self.last_path = ""
		self.ask_again = True
		self.automatic_guess = False
		self.abort_check = False
		self.pause_check = False
		self.active_check = False
		self.queue_max = 0
		self.url_queue = []
		self.algorithm_queue = []
		self.reference_queue = []
		
		self.ui.actionClear_List.triggered.connect(self.action_clear_list)
		self.ui.actionResume.triggered.connect(self.action_resume)
		self.ui.actionPause.triggered.connect(self.action_pause)
		self.ui.actionStop.triggered.connect(self.action_stop)
		self.ui.actionSkip.triggered.connect(self.action_skip)
		self.ui.actionAbout.triggered.connect(self.action_about)
		self.ui.actionAdd_File.triggered.connect(self.action_add_file)
		self.ui.actionDel_Entry.triggered.connect(self.action_del_entry)
		self.ui.actionImport.triggered.connect(self.action_import_index)
		self.ui.actionExport.triggered.connect(self.action_export_index)
		
		self.action_enabler()
		
		self.thread = GenericThread(self.checksum_calc_thread)
		self.signal_update_progessbar.connect(self.update_progessbar)
		self.signal_treeview_add_new_file.connect(self.treeview_add_new_file)
		self.thread.start()
	
	def action_enabler(self):
		if self.active_check:
			self.ui.actionSkip.setEnabled(True)
			if self.pause_check:
				self.ui.actionResume.setEnabled(True)
				self.ui.actionPause.setEnabled(False)
			else:
				self.ui.actionResume.setEnabled(False)
				self.ui.actionPause.setEnabled(True)
			if self.abort_check:
				self.ui.actionStop.setEnabled(False)
			else:
				self.ui.actionStop.setEnabled(True)
		else:
			self.ui.actionStop.setEnabled(False)
			self.ui.actionSkip.setEnabled(False)
			self.ui.actionResume.setEnabled(False)
			self.ui.actionPause.setEnabled(False)
	
	# Actions
	def action_about(self):
		about_text = (
		"<a href='http://bitrage.eu'>Hash Check</a> v%s is a lightweight hash code file checking application.<br>"
		"Copyright (C) 2013  Felix Heide<br><br>"

		"This program is free software: you can redistribute it and/or modify<br>"
		"it under the terms of the GNU General Public License as published by<br>"
		"the Free Software Foundation, either version 3 of the License, or<br>"
		"any later version.<br><br>"

		"This program is distributed in the hope that it will be useful,<br>"
		"but WITHOUT ANY WARRANTY; without even the implied warranty of<br>"
		"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.<br>"
		"See the GNU General Public License for more details.<br>"

		"You should have received a copy of the GNU General Public License<br>"
		"along with this program.  If not, see <a href='http://www.gnu.org/licenses/'>http://www.gnu.org/licenses/</a>."
		) % __version__
		QtWidgets.QMessageBox.about(self, "About Hash Check", about_text)
		
	def action_add_file(self):
		files = QtWidgets.QFileDialog.getOpenFileNames(self, "Add files to check for their hashsums", self.last_path)
		if not files:
			return False
		set_hash_algorithm = self.ui.comboBox.currentText()
		for filepath in files:
			hash_reference, believed_hash_algorithm = self.extract_hash_from_filename(filepath)
			self.add_file_to_queue(filepath, set_hash_algorithm, hash_reference, believed_hash_algorithm)
			self.last_path = os.path.dirname(filepath)
			
	def action_import_index(self):
		filepath = QtWidgets.QFileDialog.getOpenFileName(self, "Import checksum index file", self.last_path, "Checksum index files (*.sfv *.md5 *.sha* *sum*)")
		if not filepath:
			return False
		set_hash_algorithm = self.ui.comboBox.currentText()
		self.parse_hash_list_file(filepath, set_hash_algorithm)
		self.last_path = os.path.dirname(filepath)
		self.ask_again = True
		self.automatic_guess = False
		
	def action_export_index(self):
		filepath, filter = QtWidgets.QFileDialog.getSaveFileName(self, "Export checksums to index file", self.last_path, "SFV file (*.sfv);;MD5 file (*.md5);;SHA1 file (*.sha1)")
		if not filepath:
			return False
		filter_to_algorithm = {"SFV file (*.sfv)":"CRC32", "MD5 file (*.md5)":"MD5", "SHA1 file (*.sha1)":"SHA1"}
		set_hash_algorithm = filter_to_algorithm[filter]
		self.last_path = os.path.dirname(filepath)
		hashlist = []
		item_count = self.ui.treeWidget.topLevelItemCount()
		for item_index in range(item_count):
			row = self.ui.treeWidget.topLevelItem(item_index)
			if row.text(1) != set_hash_algorithm:
				continue
			if set_hash_algorithm == "CRC32":
				hashlist.append("%s %s" % (row.text(0), row.text(2).lower()))
			else:
				hashlist.append("%s *%s" % (row.text(2).lower(), row.text(0)))
		if hashlist:
			with open(filepath, 'w') as f:
				for line in hashlist:
					f.write("%s\n" % line)
			
	def action_del_entry(self):
		root = self.ui.treeWidget.invisibleRootItem()
		for item in self.ui.treeWidget.selectedItems():
			root.removeChild(item)
		
	def action_skip(self):
		self.abort_check = True
		if not self.url_queue:
			self.active_check = False
			self.action_enabler()
		
	def action_pause(self):
		self.pause_check = True
		self.action_enabler()
		
	def action_resume(self):
		self.pause_check = False
		self.action_enabler()
		
	def action_clear_list(self):
		self.ui.treeWidget.clear()
		self.ui.treeWidget.resizeColumnToContents(0)
		self.ui.treeWidget.resizeColumnToContents(1)
		self.ui.treeWidget.resizeColumnToContents(2)
		self.ui.treeWidget.resizeColumnToContents(3)
		
	def action_stop(self):
		self.pause_check = False
		self.abort_check = True
		self.queue_max = 0
		self.url_queue = []
		self.algorithm_queue = []
		self.reference_queue = []
		self.ui.progressBar.setValue(0)
		self.ui.progressBarQueue.setValue(0)
		self.active_check = False
		self.action_enabler()
		
	# Threads
	def checksum_calc_thread(self):
		while True:
			time.sleep(0.1)
			if not self.url_queue and not self.algorithm_queue and not self.reference_queue:
				self.queue_max = 0
				self.active_check = False
				continue
			if len(self.url_queue) != len(self.algorithm_queue) or len(self.algorithm_queue) != len(self.reference_queue):
				self.active_check = False
				continue
			self.active_check = True
			url = self.url_queue.pop(0)
			algorithm = self.algorithm_queue.pop(0)
			reference = self.reference_queue.pop(0)
			hash = self.hashsum(self.algo_dict[algorithm], url)
			self.signal_treeview_add_new_file.emit(algorithm, url, hash, reference)
			self.action_enabler()
		
	def update_progessbar(self, progress):
		self.ui.progressBar.setValue(progress)
		self.ui.progressBarQueue.setValue(round((self.queue_max-len(self.url_queue))/(self.queue_max + 0.000000000001) * 100))
		self.action_enabler()
		
	# Events
	def dragEnterEvent(self, event):
		if event.mimeData().hasUrls:
			event.accept()
		else:
			event.ignore()

	def dragMoveEvent(self, event):
		if event.mimeData().hasUrls:
			event.setDropAction(QtCore.Qt.CopyAction)
			event.accept()
		else:
			event.ignore()

	def dropEvent(self, event):
		if event.mimeData().hasUrls:
			event.setDropAction(QtCore.Qt.CopyAction)
			event.accept()
			set_hash_algorithm = self.ui.comboBox.currentText()
			for url in event.mimeData().urls():
				filepath = url.toLocalFile()
				filename = os.path.basename(filepath)
				filetitle, fileext = os.path.splitext(filename)
				if any(x in fileext for x in ["sfv", "md5", "sha1", "sha224", "sha256", "sha384", "sha512"]):
					self.parse_hash_list_file(filepath, set_hash_algorithm)
				elif any(x in filetitle for x in ["md5sum", "shasum", "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum"]):
					self.parse_hash_list_file(filepath, set_hash_algorithm)
				else:
					hash_reference, believed_hash_algorithm = self.extract_hash_from_filename(filepath)
					self.add_file_to_queue(filepath, set_hash_algorithm, hash_reference, believed_hash_algorithm)
			self.ask_again = True
			self.automatic_guess = False
		else:
			event.ignore()
			
	# Helper
	def parse_hash_list_file(self, filepath, set_hash_algorithm):
		hash_pattern = re.compile(".*?([a-fA-F0-9]{8,128}).*")
		with open(filepath) as f:
			for line in f:
				hash, filename = ("", "")
				if line.startswith(";"):
					continue
				split_line = line.split()
				if len(split_line) == 2:
					if hash_pattern.match(split_line[0]):
						hash, filename = split_line
					elif hash_pattern.match(split_line[1]):
						filename, hash = split_line
				if "*" in filename:
					filename = filename.split("*")[-1]
				hash_reference = hash.upper()
				believed_hash_algorithm = algo_length_dict[len(hash_reference)]
				self.add_file_to_queue(os.path.join(os.path.dirname(filepath), filename), set_hash_algorithm, hash_reference, believed_hash_algorithm)
					
	def add_file_to_queue(self, filepath, set_hash_algorithm, hash_reference=None, believed_hash_algorithm=None):
		if not believed_hash_algorithm:
			self.algorithm_queue.append(set_hash_algorithm)
			self.reference_queue.append(None)
		else:
			self.reference_queue.append(hash_reference)
			if self.ask_again:
				if believed_hash_algorithm != set_hash_algorithm:
					msg_box = QtWidgets.QMessageBox(self)
					msg_box.setWindowTitle('Which hash algorithm to use')
					msg_box.setText(os.path.basename(filepath))
					msg_box.setInformativeText("The hash algorithm is believed to be %s. Would you like to use automatic guess instead of the selected %s?" % (believed_hash_algorithm, set_hash_algorithm))
					msg_box.setStandardButtons(QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.YesToAll | QtWidgets.QMessageBox.No | QtWidgets.QMessageBox.NoToAll)
					msg_box.setDefaultButton(QtWidgets.QMessageBox.YesToAll)
					reply = msg_box.exec_()
					if reply == QtWidgets.QMessageBox.Yes:
						self.algorithm_queue.append(believed_hash_algorithm)
					elif reply == QtWidgets.QMessageBox.YesToAll:
						self.algorithm_queue.append(believed_hash_algorithm)
						self.ask_again = False
						self.automatic_guess = True
					elif reply == QtWidgets.QMessageBox.No:
						self.algorithm_queue.append(set_hash_algorithm)
					elif reply == QtWidgets.QMessageBox.NoToAll:
						self.algorithm_queue.append(set_hash_algorithm)
						self.ask_again = False
				else:
					self.algorithm_queue.append(set_hash_algorithm)
			else:
				if self.automatic_guess:
					self.algorithm_queue.append(believed_hash_algorithm)
				else:
					self.algorithm_queue.append(set_hash_algorithm)
		self.url_queue.append(filepath)
		self.queue_max += 1
		
	def extract_hash_from_filename(self, filepath):
		hash_pattern = re.compile(".*[\[\(]([a-fA-F0-9]{8,128})[\]\)].*")
		hash = None
		hash_algo = None
		if hash_pattern.match(os.path.basename(filepath)):
			hash = hash_pattern.match(os.path.basename(filepath)).group(1)
			if len(hash) in algo_length_dict:
				hash_algo = algo_length_dict[len(hash)]
		return (hash, hash_algo)
			
	def treeview_add_new_file(self, algorithm, filepath, hash, hash_reference=None):
		row = QtWidgets.QTreeWidgetItem()
		row.filepath = filepath
		row.setIcon(0, self.icons["blank"])
		row.setText(0, os.path.basename(filepath))
		row.setText(1, algorithm)
		row.setText(2, hash)
		if hash == "N/A":
			row.setIcon(0, self.icons["error"])
		elif self.abort_check:
			self.abort_check = False
			row.setIcon(0, self.icons["question"])
		elif hash_reference:
			if hash_reference == hash:
				row.setIcon(0, self.icons["accept"])
			else:
				row.setIcon(0, self.icons["exclamation"])
		row.setText(3, hash_reference)
		self.ui.treeWidget.addTopLevelItem(row)
		self.ui.treeWidget.update()
		self.ui.treeWidget.resizeColumnToContents(0)
		self.ui.treeWidget.resizeColumnToContents(1)
		self.ui.treeWidget.resizeColumnToContents(2)
		self.ui.treeWidget.resizeColumnToContents(3)

	def hashsum(self, hashname, filename):
		self.abort_check = False
		try:
			hash = getattr(hashlib, hashname)()
		except AttributeError:
			hash = hashlib.new(hashname)
		if not os.path.exists(filename):
			self.signal_update_progessbar.emit(100)
			return "N/A"
		total_size = os.path.getsize(filename)
		total_read = 0
		last_output = 0
		chunk_size = 128*hash.block_size
		with open(filename,'rb') as f: 
			for chunk in iter(lambda: f.read(chunk_size), b''): 
				hash.update(chunk)
				total_read += chunk_size
				progress = int(total_read/total_size * 100)
				if progress >= last_output + 5:
					last_output = progress
					self.signal_update_progessbar.emit(progress)
				while self.pause_check:
					time.sleep(0.1)
				if self.abort_check:
					self.signal_update_progessbar.emit(0)
					return hash.hexdigest().upper()
		self.abort_check = False
		self.signal_update_progessbar.emit(100)
		return hash.hexdigest().upper()

def on_close(win):
	print("Goodbye")
		
	
if __name__ == "__main__":
	if getattr(sys, 'frozen', False):
		# The application is frozen
		os.chdir(os.path.dirname(os.path.abspath(sys.executable)))
	else:
		# The application is not frozen
		os.chdir(os.path.dirname(os.path.abspath(__file__)))
	app = QtWidgets.QApplication(sys.argv)
	win = Checksum_Calculator()
	app.aboutToQuit.connect(functools.partial(on_close, win=win))
	sys.exit(app.exec_())