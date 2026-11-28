import configparser


class Config:
	"""Encapsules a dictionary that represents config values set by the user."""


	def __init__(self, path, defaults, error_callback=None, update_constants_callback=None):
		"""TODO"""

		# Parameters
		self.PATH = path
		self.DEFAULTS = defaults
		self.show_error = error_callback
		self.update_config_constants = update_constants_callback

		# Create dictionary with default config settings
		self.data = {}
		self.comments = {}
		for section_name, section_items in self.DEFAULTS:
			self.data.setdefault(section_name, {})
			for item_name, item_value, *item_comment in section_items:
				self.data[section_name].setdefault(item_name, item_value)
				# A setting can have a comment (optional), which is written above it in the config file
				if item_comment:
					self.comments[(section_name, item_name)] = item_comment[0]
		
		# Try to read settings from the config file and update the dictionary accordingly
		parser = configparser.RawConfigParser()
		try:
			parser.read(self.PATH)
			for section_name, section in self.data.items():
				try:
					for item_name in section:
						try:
							from_file = parser.get(section_name, item_name)
							if from_file in ("true", "True", "TRUE"):
								self.data[section_name][item_name] = True
							elif from_file in ("false", "False", "FALSE"):
								self.data[section_name][item_name] = False
							elif from_file in ("none", "None", "NONE"):
								self.data[section_name][item_name] = None
							else:
								t = type(self.data[section_name][item_name])
								self.data[section_name][item_name] = t(from_file)
						except (configparser.NoSectionError, configparser.NoOptionError):
							print(f"[WARNING] Option \"{item_name}\" missing from section \"{section_name}\" of the config file at \"{self.PATH}\". Using default value.")
						except Exception as e:
							self.show_error("An error occurred while reading a config item.", no_ui=True)
				except Exception as e:
					self.show_error("An error occurred while reading a config section.", no_ui=True)
		except Exception as e:
			self.show_error("An error occurred while reading the config.", no_ui=True)

		# Update config file
		self.update()


	def __getitem__(self, key):
		"""TODO"""
		return self.data.__getitem__(key)


	def __setitem__(self, key, value):
		"""TODO"""
		return self.data.__setitem__(key, value)


	def update(self):
		"""Writes config values set by the user to the config file."""
		# Written in the same format as `configparser` writes it, which can't write comments
		with open(self.PATH, 'wt') as file:
			for section_name, section in self.data.items():
				file.write(f"[{section_name}]\n")
				for item_name, item_value in section.items():
					if (section_name, item_name) in self.comments:
						file.write(f"\n# {self.comments[(section_name, item_name)]}\n")
					item_value = str(item_value).replace("\n", "\n\t")
					file.write(f"{item_name} = {item_value}\n")
				file.write("\n")
		try:
			self.update_config_constants(self)
		except:
			pass
