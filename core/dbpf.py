import io
import struct


class DBPF:
	"""TODO include credits to original php file"""


	MAX_DECOMPRESSED_SIZE = 4_000_000	# bytes. The subfiles read here are a few KB, so more means the file is broken or malicious


	def __init__(self, filename, offset=0, error_callback=None, require_identifier=True):
		"""TODO"""

		print(f'Parsing "{filename}"...')

		self.filename = filename
		self.offset = offset
		self.show_error = error_callback
		self.require_identifier = require_identifier

		self.NONSENSE_BYTE_OFFSET = 9

		# Open file to read bytes
		self.file = open(self.filename, 'rb')

		# Advance to offset
		if self.offset > 0:
			self.file.seek(self.offset)

		# Read the identifier
		self.identifier = self.file.read(4).decode()		# Always "DBPF"
		if self.require_identifier and self.identifier != "DBPF":
			raise Exception()

		# Read the header
		self.majorVersion = self.read_UL4()					# Always 1
		self.minorVersion = self.read_UL4()					# Always 0
		self.reserved = self.file.read(12)
		self.dateCreated = self.read_UL4()
		self.dateModified = self.read_UL4()
		self.indexMajorVersion = self.read_UL4()
		self.indexCount = self.read_UL4()
		self.indexOffset = self.read_UL4()
		self.indexSize = self.read_UL4()
		self.holesCount = self.read_UL4()
		self.holesOffset = self.read_UL4()
		self.holesSize = self.read_UL4()
		self.indexMinorVersion = self.read_UL4() - 1
		self.reserved2 = self.file.read(32)
		self.header_end = self.file.tell()

		# Seek to index table
		self.file.seek(offset + self.indexOffset)

		# Read index table
		self.indexData = []
		for index in range(0, self.indexCount):
			self.indexData.append({})
			self.indexData[index]['typeID'] = self.read_ID()
			self.indexData[index]['groupID'] = self.read_ID()
			self.indexData[index]['instanceID'] = self.read_ID()
			if (self.indexMajorVersion == 7) and (self.indexMinorVersion == 1):
				self.indexData[index]['instanceID2'] = self.read_ID()
			self.indexData[index]['offset'] = self.read_UL4()
			self.indexData[index]['filesize'] = self.read_UL4()
			#self.indexData[index]['compressed'] = #TODO
			#self.indexData[index]['truesize'] = #TODO

		#print(f"DBPF v{self.majorVersion}.{self.minorVersion}")


	def __enter__(self):

		return self
	

	def __exit__(self, exc_type, exc_value, traceback):

		self.close()
		return False


	def close(self):

		self.file.close()


	def decompress(self, length):

		buf = ""			# TODO what does this do?
		answer = bytearray()	# a bytearray, since appending to bytes copies them each time
		answerlen = 0		# TODO what does this do?
		numplain = ""		# TODO what does this do?
		numcopy = ""		# TODO what does this do?
		offset = ""			# TODO what does this do?

		try:

			# Read until there's nothing left to read
			while length > 0 and len(answer) <= self.MAX_DECOMPRESSED_SIZE:
				
				# Read control char
				cc = self.read_UL1(self.file) #TODO Line causes errors on older versions of DBPF but doesn't seem to affect anything. Always fails with 9 bytes remaining.
				length -= 1

				# For development
				#print(f"Control char is {cc}, length remaining is {length}.")

				if cc >= 252:	#0xFC

					numplain = cc & 3										#3 = 0x03
					numplain = length if numplain > length else numplain
					
					numcopy = 0
					offset = 0

				elif cc >= 224:	#0xE0

					numplain = (cc - 223) << 2								#223 = 0xdf

					numcopy = 0
					offset = 0

				elif cc >= 192:	#0xC0

					length -= 3

					byte1 = self.read_UL1(self.file)
					byte2 = self.read_UL1(self.file)
					byte3 = self.read_UL1(self.file)

					numplain = cc & 3										#3 = 0x03
					
					numcopy = ((cc & 12) << 6) + 5 + byte3 					#12 = 0x0c
					offset = ((cc & 16) << 12) + (byte1 << 8) + byte2 		#16 = 0x10

				elif cc >= 128: #0x80

					length -= 2

					byte1 = self.read_UL1(self.file)
					byte2 = self.read_UL1(self.file)

					numplain = (byte1 & 192) >> 6 							#192 = 0xc0

					numcopy = (cc & 63) + 4 								#63 = 0x3f
					offset = ((byte1 & 63) << 8) + byte2 					#63 = 0x3f

				else:

					length -= 1

					byte1 = self.read_UL1(self.file)

					numplain = cc & 3 										#3 = 0x03

					numcopy = ((cc & 28) >> 2) + 3 							#28 = 0x1c
					offset = ((cc & 96) << 3) + byte1 						#96 = 0x60

				length -= numplain

				# This section basically copies the parts of the string to the end of the buffer:
				if numplain > 0:

					buf = self.file.read(numplain)

					answer += buf

				fromoffset = len(answer) - (offset + 1)  # 0 == last char
				for index in range(numcopy):

					#print(str(answer))
					#print(str(cc))
					#print(str(offset))
					#print(str(fromoffset))
					
					#TODO remove try and except block. decompression algorithm breaks with a control char of 206. the offset becomes larger than the length of the answer, causing a negative fromindex and an indexing error. for now it does not seem to affect city coordinates
					try:
						answer.append(answer[fromoffset + index]) #substr(fromoffset + index, 1)
					except Exception as e:
						#show_error(e) #TODO
						return io.BytesIO(answer)
					
				answerlen += numplain
				answerlen += numcopy

		except Exception:

			self.show_error(f"An error occurred while decompressing \"{self.filename}\" with {length} bytes remaining.")

		if len(answer) > self.MAX_DECOMPRESSED_SIZE:
			raise ValueError(f"\"{self.filename}\" decompresses to more than {self.MAX_DECOMPRESSED_SIZE} bytes.")

		return io.BytesIO(answer)


	def read_UL1(self, file=None):
		"""TODO"""
		if file is None:
			file = self.file
		return struct.unpack('<B', file.read(1))[0]


	def read_UL2(self, file=None):
		"""TODO"""
		if file is None:
			file = self.file
		return struct.unpack('<H', file.read(2))[0]
	
	
	def read_UL4(self, file=None):
		"""TODO"""
		if file is None:
			file = self.file
		return struct.unpack('<L', file.read(4))[0]
	
	
	#def read_UL8(self, file=None):
	#	if file is None:
	#		file = self.file
	#	return struct.unpack("<q", file.read(8))[0]


	def read_unistr(self, file=None, length=None):
		if file is None:
			file = self.file
		if length is None:
			length = struct.unpack("<L", file.read(4))[0]
		return file.read(length).decode()


	def read_nullstring(self, file=None):
		if file is None:
			file = self.file
		text = ""
		while True:
			byte = file.read(1)
			if byte == b"\x00":
				return text
			else:
				text += byte.decode()


	def read_ID(self, file=None):
		"""TODO"""
		if file is None:
			file = self.file
		return file.read(4)[::-1].hex()


	def get_indexData_entry_by_type_ID(self, type_id):
		"""TODO"""
		for entry in self.indexData:
			if entry['typeID'] == type_id:
				return entry


	def goto_subfile(self, type_id):
		"""TODO"""
		entry = self.get_indexData_entry_by_type_ID(type_id)
		self.file.seek(entry['offset'])
		#print(entry['offset'] + 9)


	def get_subfile_size(self, type_id):
		"""TODO"""
		entry = self.get_indexData_entry_by_type_ID(type_id)
		return entry['filesize']


	def get_subfile_header(self, type_id):
		"""TODO"""
		#self.goto_subfile(type_id)
		#return (self.read_UL4(), self.read_ID(), ) #TODO how to read these values?
		pass


	def decompress_subfile(self, type_id):
		"""TODO"""
		#print('Decompressing "' + type_id + '"...')
		self.goto_subfile(type_id)
		self.file.read(self.NONSENSE_BYTE_OFFSET)
		return self.decompress(self.get_subfile_size(type_id))


class SC4Config(DBPF):


	def __init__(self, *args, **kwargs):

		super().__init__(*args, **kwargs)

	
	def get_simcity_4_cfg(self):

		data = self.decompress_subfile("a9dd6e06")

		self.simcity_4_cfg = {}

		data.seek(110)														# 0x06E
		self.simcity_4_cfg["LastCityName"] = self.read_nullstring(data)

		data.seek(622)														# 0x26E
		self.simcity_4_cfg["LastMayorName"] = self.read_nullstring(data)

		data.seek(3774)														# 0xEBE
		self.simcity_4_cfg["LastRegionName"] = self.read_nullstring(data)

		return self.simcity_4_cfg


class SC4Savegame(DBPF):


	def __init__(self, *args, **kwargs):

		super().__init__(*args, **kwargs)

	
	def get_SC4ReadRegionalCity(self):

		#print(f'Parsing region view subfile of "{self.filename}"...')

		# Decompress the subfile and get the data as a bytes stream
		data = self.decompress_subfile("ca027edb")

		# Dictionary to return
		self.SC4ReadRegionalCity = {}

		try:

			# DBPF file version
			self.SC4ReadRegionalCity['majorVersion'] = self.read_UL2(data)
			self.SC4ReadRegionalCity['minorVersion'] = self.read_UL2(data)
			version = (self.SC4ReadRegionalCity['majorVersion'], self.SC4ReadRegionalCity['minorVersion'])

			#print(f"Parsing region view subfile (v{self.SC4ReadRegionalCity['majorVersion']}.{self.SC4ReadRegionalCity['minorVersion']}) of {self.filename}.")

			# City location
			self.SC4ReadRegionalCity['tileXLocation'] = self.read_UL4(data)
			self.SC4ReadRegionalCity['tileYLocation'] = self.read_UL4(data)
			
			# City size
			self.SC4ReadRegionalCity['citySizeX'] = self.read_UL4(data)
			self.SC4ReadRegionalCity['citySizeY'] = self.read_UL4(data)
			
			# City population 
			self.SC4ReadRegionalCity['residentialPopulation'] = self.read_UL4(data)
			self.SC4ReadRegionalCity['commercialPopulation'] = self.read_UL4(data)
			self.SC4ReadRegionalCity['industrialPopulation'] = self.read_UL4(data)

			# Unknown
			if version > (1,9):
				data.read(4) #self.SC4ReadRegionalCity['unknown1'] = data.read(4) #TODO read float

			# Mayor rating, difficulty and tutorial mode flag
			if version > (1,10):
				self.SC4ReadRegionalCity['mayorRating'] = self.read_UL1(data)
			self.SC4ReadRegionalCity['starCount'] = self.read_UL1(data)
			self.SC4ReadRegionalCity['tutorialFlag'] = self.read_UL1(data)

			# Not sure what this is for
			self.SC4ReadRegionalCity['cityGUID'] = self.read_UL4(data)

			# Unknown
			data.read(20)
			#self.SC4ReadRegionalCity['unknown5'] = self.read_UL4(data)
			#self.SC4ReadRegionalCity['unknown6'] = self.read_UL4(data)
			#self.SC4ReadRegionalCity['unknown7'] = self.read_UL4(data)
			#self.SC4ReadRegionalCity['unknown8'] = self.read_UL4(data)
			#self.SC4ReadRegionalCity['unknown9'] = self.read_UL4(data)

			# Gamemode
			self.SC4ReadRegionalCity['modeFlag'] = self.read_UL1(data)

			# City name
			self.SC4ReadRegionalCity['cityName'] = self.read_unistr(data)

			# Former city name
			self.SC4ReadRegionalCity['formerCityName'] = self.read_unistr(data)

			# Mayor name
			self.SC4ReadRegionalCity['mayorName'] = self.read_unistr(data)

			#TODO keep reading subfile

		except Exception:

			self.show_error(f"An error occurred while parsing the region view subfile (v{self.SC4ReadRegionalCity['majorVersion']}.{self.SC4ReadRegionalCity['minorVersion']}) of \"{self.filename}\".")

		self.SC4ReadRegionalCity.setdefault("mayorRating", 0)
		self.SC4ReadRegionalCity.setdefault("cityName", None)
		self.SC4ReadRegionalCity.setdefault("mayorName", None)

		return self.SC4ReadRegionalCity


	def get_cSC4BudgetSimulator(self):

		# Decompress the subfile and get the data as a bytes stream
		data = self.decompress_subfile("e990be01")

		# Dictionary to return
		self.cSC4BudgetSimulator = {}

		# Not decoded yet
		data.read(14)

		# Total funds
		self.cSC4BudgetSimulator["totalFunds"] = struct.unpack("<q", data.read(8))[0]

		return self.cSC4BudgetSimulator


	REGION_VIEW_VERSION = (1, 13)
	PROPERTY_SIZES = {1: 1, 2: 2, 3: 4, 7: 4, 8: 8, 9: 4, 11: 1}	# bytes per value, by value type


	def get_region_view_data(self):
		"""Returns the decompressed region view subfile, cut to the size in its header (the decompression reads a few bytes past the subfile)."""

		self.goto_subfile("ca027edb")
		header = self.file.read(self.NONSENSE_BYTE_OFFSET)
		if header[4:6] != b"\x10\xfb":
			raise ValueError(f"The region view subfile of \"{self.filename}\" isn't compressed.")
		size = int.from_bytes(header[6:9], "big")

		return self.decompress(self.get_subfile_size("ca027edb")).getvalue()[:size]


	def skip(self, data, size):
		"""Skips `size` bytes, or raises an error if there are fewer left."""

		if len(data.read(size)) != size:
			raise ValueError("Unexpected end of data.")


	def skip_properties(self, data):
		"""Skips the list of properties of a neighbour connection or deal, or raises an error if it has one that isn't known."""

		if self.read_UL2(data) != 2:
			raise ValueError("Unknown property list version.")
		for _ in range(self.read_UL4(data)):
			self.skip(data, 12)
			value_type = self.read_UL1(data)
			key_type = self.read_UL1(data)
			self.skip(data, 2)
			if value_type == 12:
				self.skip(data, self.read_UL4(data))
			elif key_type == 0x80:
				self.skip(data, self.read_UL4(data) * self.PROPERTY_SIZES[value_type])
			else:
				self.skip(data, self.PROPERTY_SIZES[value_type])


	def read_region_view(self):
		"""Reads the region view subfile to its end and returns what the server needs of it to keep neighbours in sync, as a dictionary, or `None` if the subfile isn't laid out as expected (so nothing is misread):

		- `tile`, `size`, `established`: the city's tile, its size in tiles, and whether it's established
		- `connections`: the city's connections to its neighbours, as `(type, x, z)` (the cell just outside the city's edge)
		- `pending`: the connection changes waiting for the city, 13 bytes each (type, `x`, `z`, added or removed). SC4 adds one to a neighbour when a connection to it is made or removed, and builds or removes the neighbour's end when that city is loaded
		- `deals`: two lists of neighbour deal records (eg. selling power). When SC4 saves a city, it writes the neighbour's deals with other cities in its first list and its deals with the saved city in its second, the same records as in the saved city
		- `data` and the `pending_range` and `deals_range` in it, for `write_region_view`"""

		raw = self.get_region_view_data()
		data = io.BytesIO(raw)
		region_view = {"data": raw, "connections": [], "pending": [], "deals": [[], []]}

		try:

			if (self.read_UL2(data), self.read_UL2(data)) != self.REGION_VIEW_VERSION:
				return None

			region_view["tile"] = (self.read_UL4(data), self.read_UL4(data))
			region_view["size"] = (self.read_UL4(data), self.read_UL4(data))

			# Population, mayor rating, difficulty and so on
			self.skip(data, 43)
			region_view["established"] = self.read_UL1(data) != 0

			# City name, mayor name, description and so on
			for _ in range(7):
				self.skip(data, self.read_UL4(data))
			self.skip(data, 16)

			# Three lists of populations, and the tax rates
			for _ in range(3):
				self.skip(data, self.read_UL4(data) * 8)
			self.skip(data, self.read_UL4(data) * 4)

			# Connections
			for _ in range(self.read_UL4(data)):
				if self.read_UL2(data) != 1:
					return None
				region_view["connections"].append(struct.unpack("<Iii", data.read(12)))
				self.skip(data, 9)
				self.skip_properties(data)

			# Pending connection changes
			start = data.tell()
			for _ in range(self.read_UL4(data)):
				change = data.read(13)
				if len(change) != 13:
					return None
				region_view["pending"].append(change)
			region_view["pending_range"] = (start, data.tell())

			# Budget and income, then what the city produces, imports and so on
			self.skip(data, 16)
			self.skip(data, self.read_UL4(data) * 44)

			# Neighbour deals
			start = data.tell()
			for deals in region_view["deals"]:
				for _ in range(self.read_UL4(data)):
					deal_start = data.tell()
					if self.read_UL2(data) != 5:
						return None
					self.skip(data, 64)
					self.skip_properties(data)
					self.skip(data, 4)
					deals.append(raw[deal_start:data.tell()])
			region_view["deals_range"] = (start, data.tell())

			# Airports and seaports. SC4 can leave old bytes after them, which stay as they are
			for _ in range(self.read_UL4(data)):
				self.skip(data, 4)
				self.skip(data, self.read_UL4(data) * 12)

		except (struct.error, ValueError, KeyError):

			return None

		return region_view


	@staticmethod
	def get_neighbor_deal_tiles(deal):
		"""Returns the two tiles of a neighbour deal record: one in each city."""

		return struct.unpack_from("<ii", deal, 6), struct.unpack_from("<ii", deal, 34)


	def write_region_view(self, region_view, filename):
		"""Writes a copy of the savegame to `filename` with the `pending` connection changes and the `deals` of `region_view` (as returned by `read_region_view`). Only the region view subfile and the directory (which has its decompressed size) change. They're written after the rest of the file, followed by a new index, so every other subfile keeps its bytes and where it is."""

		pending = struct.pack("<I", len(region_view["pending"])) + b"".join(region_view["pending"])
		deals = b""
		for deals_list in region_view["deals"]:
			deals += struct.pack("<I", len(deals_list)) + b"".join(deals_list)
		data = region_view["data"]
		data = data[:region_view["pending_range"][0]] + pending + data[region_view["pending_range"][1]:region_view["deals_range"][0]] + deals + data[region_view["deals_range"][1]:]

		self.file.seek(0)
		original = self.file.read()

		if (self.indexMajorVersion == 7) and (self.indexMinorVersion == 1):
			id_count = 4
		else:
			id_count = 3

		region_view_entry = self.get_indexData_entry_by_type_ID("ca027edb")
		directory_entry = self.get_indexData_entry_by_type_ID("e86b1eef")
		if directory_entry is None:
			raise ValueError(f"\"{self.filename}\" has no directory.")

		# The directory lists the decompressed size of every compressed subfile
		directory = bytearray(original[directory_entry['offset']:directory_entry['offset'] + directory_entry['filesize']])
		region_view_key = b"".join(bytes.fromhex(region_view_entry[name])[::-1] for name in ['typeID', 'groupID', 'instanceID', 'instanceID2'][:id_count])
		directory_entry_size = id_count * 4 + 4
		found = False
		for position in range(0, len(directory) - directory_entry_size + 1, directory_entry_size):
			if directory[position:position + id_count * 4] == region_view_key:
				directory[position + id_count * 4:position + directory_entry_size] = struct.pack("<I", len(data))
				found = True
		if not found:
			raise ValueError(f"The directory of \"{self.filename}\" doesn't have the region view subfile.")

		# If the savegame was written like this before, replace what was written then instead of adding more
		end = len(original)
		if region_view_entry['offset'] + region_view_entry['filesize'] == directory_entry['offset'] and directory_entry['offset'] + directory_entry['filesize'] == self.indexOffset and self.indexOffset + self.indexSize == len(original):
			end = region_view_entry['offset']

		compressed = self.compress(data)
		region_view_offset = end
		directory_offset = region_view_offset + len(compressed)
		index_offset = directory_offset + len(directory)

		index = b""
		for entry in self.indexData:
			key = b"".join(bytes.fromhex(entry[name])[::-1] for name in ['typeID', 'groupID', 'instanceID', 'instanceID2'][:id_count])
			entry_offset = entry['offset']
			entry_size = entry['filesize']
			if entry is region_view_entry:
				entry_offset = region_view_offset
				entry_size = len(compressed)
			elif entry is directory_entry:
				entry_offset = directory_offset
				entry_size = len(directory)
			index += key + struct.pack("<II", entry_offset, entry_size)

		header = bytearray(original[:self.header_end])
		header[40:48] = struct.pack("<II", index_offset, len(index))

		with open(filename, "wb") as file:
			file.write(header + original[len(header):end] + compressed + directory + index)


	@staticmethod
	def compress(data):
		"""Returns `data` QFS compressed in the simplest way, as plain bytes only: a valid compressed subfile, just not a smaller one."""

		compressed = bytearray()
		position = 0
		while len(data) - position >= 4:
			count = min(112, (len(data) - position) // 4 * 4)
			compressed.append(0xE0 + count // 4 - 1)
			compressed += data[position:position + count]
			position += count
		compressed.append(0xFC + len(data) - position)
		compressed += data[position:]

		return struct.pack("<I", len(compressed) + 9) + b"\x10\xfb" + len(data).to_bytes(3, "big") + bytes(compressed)


if __name__ == "__main__":

	import sys

	def error(e):
		print(f"{e}")

	filename = sys.argv[1]

	if filename.endswith(".sc4"):

		savegame = SC4Savegame(filename, 0, error)

		print(savegame.indexData)

		print(savegame.indexOffset)

		with open("SC4ReadRegionalCity.sc4", "wb") as file:
			file.write(savegame.decompress_subfile("ca027edb").read())

		with open("cSC4BudgetSimulator.sc4", "wb") as file:
			file.write(savegame.decompress_subfile("e990be01").read())

		print(savegame.get_SC4ReadRegionalCity())
		print(savegame.get_cSC4BudgetSimulator())

	elif filename.endswith(".cfg"):

		cfg = SC4Config(filename, 0, error)

		print(cfg.get_simcity_4_cfg())

		#print(f"{dbpf.majorVersion}.{dbpf.minorVersion}")

		#for entry in dbpf.indexData:
		#	with open(f"{entry['typeID']}.cfg", "wb") as file:
		#		file.write(dbpf.decompress_subfile(entry["typeID"]).read())