import binaryninja
from binaryninja import PluginCommand, PluginCommandType
from binaryninjaui import Menu, UIAction, UIActionContext, UIActionHandler  # type: ignore

from typing import overload, Any


# TODO: idk how to make the plugin name abstraction properly, change it later
_PLUGIN_NAME: str | None = None


class Action:
	"""
	Action base class.

	Attributes
	----------
	display_name: str
		The string that is displayed in the menu.
	description: str
		Description of the action. Currently this is not used by BinaryNinja,
		so it mostly for devs to understand.
	desired_hotkey: str
		Hotkey that is desired to bind to. This hotkey is used as a default in BinaryNinja.
	logger: binaryninja.Logger
		Logger object.
	"""

	display_name: str = ""
	description: str = ""
	desired_hotkey: str = ""
	logger: binaryninja.Logger | None = None

	def __init__(self):
		assert _PLUGIN_NAME is not None, "PLUGIN_NAME must be set"
		self.logger = binaryninja.log.Logger(0, f"{_PLUGIN_NAME}.{self.short_name}")

	@property
	def short_name(self):
		return self.__class__.__name__

	def register(self):
		raise NotImplementedError

	def unregister(self):
		raise NotImplementedError


class PyToolsPluginCommand(Action):
	"""
	Wrapper class for binaryninja.PluginCommand registration.

	Attributes
	----------
	type: binaryninja.PluginCommandType
		The type of plugincommand, used to decide which registration handler should use.
	"""

	type: PluginCommandType | None = None

	_type_to_handler = {
		PluginCommandType.DefaultPluginCommand: PluginCommand.register,
		PluginCommandType.AddressPluginCommand: PluginCommand.register_for_address,
		PluginCommandType.RangePluginCommand: PluginCommand.register_for_range,
		PluginCommandType.FunctionPluginCommand: PluginCommand.register_for_function,
		PluginCommandType.LowLevelILFunctionPluginCommand: PluginCommand.register_for_low_level_il_function,
		PluginCommandType.LowLevelILInstructionPluginCommand: PluginCommand.register_for_low_level_il_instruction,
		PluginCommandType.MediumLevelILFunctionPluginCommand: PluginCommand.register_for_medium_level_il_function,
		PluginCommandType.MediumLevelILInstructionPluginCommand: PluginCommand.register_for_medium_level_il_instruction,
		PluginCommandType.HighLevelILFunctionPluginCommand: PluginCommand.register_for_high_level_il_function,
		PluginCommandType.HighLevelILInstructionPluginCommand: PluginCommand.register_for_high_level_il_instruction,
		PluginCommandType.ProjectPluginCommand: PluginCommand.register_for_project,
	}

	def __init__(self):
		super().__init__()

		assert self.display_name and self.description, (
			f"Fullname and description must be filled, missing for {self.short_name}"
		)
		assert self.type is not None, (
			f"Plugin command type must be set, missing for {self.short_name}"
		)

	# fmt: off
	@overload
	def activate(self, bv: binaryninja.BinaryView): ...
	@overload
	def activate(self, bv: binaryninja.BinaryView, address: int): ...
	@overload
	def activate(self, bv: binaryninja.BinaryView, function: binaryninja.Function): ...
	@overload
	def activate(self, bv: binaryninja.BinaryView, hlil: binaryninja.HighLevelILFunction): ...
	@overload
	def activate(self, bv: binaryninja.BinaryView, hlil_instr: binaryninja.HighLevelILInstruction): ...
	@overload
	def activate(self, bv: binaryninja.BinaryView, mlil: binaryninja.MediumLevelILFunction): ...
	@overload
	def activate(self, bv: binaryninja.BinaryView, mlil_instr: binaryninja.MediumLevelILInstruction): ...
	@overload
	def activate(self, bv: binaryninja.BinaryView, llil: binaryninja.LowLevelILFunction): ...
	@overload
	def activate(self, bv: binaryninja.BinaryView, llil_instr: binaryninja.LowLevelILInstruction): ...
	@overload
	def activate(self, bv: binaryninja.BinaryView, address: int, length: int): ...

	def activate(self, *args, **kwargs) -> Any:
		raise NotImplementedError
	# fmt: on

	# fmt: off
	@overload
	def is_valid(self, bv: binaryninja.BinaryView) -> bool: ...
	@overload
	def is_valid(self, bv: binaryninja.BinaryView, address: int) -> bool: ...
	@overload
	def is_valid(self, bv: binaryninja.BinaryView, function: binaryninja.Function) -> bool: ...
	@overload 
	def is_valid(self, bv: binaryninja.BinaryView, llil: binaryninja.LowLevelILFunction) -> bool: ...
	@overload 
	def is_valid(self, bv: binaryninja.BinaryView, llil_instr: binaryninja.LowLevelILInstruction) -> bool: ...
	@overload 
	def is_valid(self, bv: binaryninja.BinaryView, mlil: binaryninja.MediumLevelILFunction) -> bool: ...
	@overload 
	def is_valid(self, bv: binaryninja.BinaryView, mlil_instr: binaryninja.MediumLevelILInstruction) -> bool: ...
	@overload 
	def is_valid(self, bv: binaryninja.BinaryView, hlil: binaryninja.HighLevelILFunction) -> bool: ...
	@overload 
	def is_valid(self, bv: binaryninja.BinaryView, hlil_instr: binaryninja.HighLevelILInstruction) -> bool: ...
	@overload 
	def is_valid(self, bv: binaryninja.BinaryView, begin: int, end: int) -> bool: ...

	def is_valid(self, *args, **kwargs) -> bool:
		raise NotImplementedError
	# fmt: off

	def register(self):
		register = self._type_to_handler[self.type]

		if self.desired_hotkey:
			self.logger.log_warn(
					f"Desired hotkey ({self.desired_hotkey}) for {self.short_name} is set, "
					"but setting default hotkey currently unavailable for PluginCommands, ignored"
				)

		register(
			f"{_PLUGIN_NAME}\\{self.display_name}",
			self.description,
			self.activate,
			self.is_valid,
		)


class PyToolsUIAction(Action):
	def __init__(self):
		super().__init__()
		assert self.display_name and self.description, "Fullname and description must be filled"

	# fmt: off
	@overload
	def activate(self): ...
	@overload
	def activate(self, context: UIActionContext): ...

	def activate(self, *args, **kwargs) -> Any:
		raise NotImplementedError
	# fmt: on

	# fmt: off
	@overload
	def is_valid(self) -> bool: return True
	@overload
	def is_valid(self, context: UIActionContext) -> bool: return True

	def is_valid(self, *args, **kwargs) -> bool:
		raise NotImplementedError
	# fmt: on

	@staticmethod
	def add_to_context_menu(is_valid_handler):
		import functools

		if is_valid_handler.__name__ != "is_valid":
			raise ValueError(
				f"add_context_menu decorator can be applied only to is_valid handlers, applied to {is_valid_handler}"
			)

		@functools.wraps(is_valid_handler)
		def wrapper(self, context):
			if not is_valid_handler(self, context):
				return False

			view = context.view
			context_menu = view.contextMenu()
			context_menu.addAction("Plugins", f"{_PLUGIN_NAME}\\{self.display_name}", "Plugins")

			return True

		return wrapper

	def register(self):
		UIAction.registerAction(f"{_PLUGIN_NAME}\\{self.display_name}", self.desired_hotkey)
		UIActionHandler.globalActions().bindAction(
			f"{_PLUGIN_NAME}\\{self.display_name}",
			UIAction(self.activate, self.is_valid),
		)
		Menu.mainMenu("Plugins").addAction(f"{_PLUGIN_NAME}\\{self.display_name}", "Plugins")


class ActionManager:
	def __init__(self) -> None:
		assert _PLUGIN_NAME is not None, "PLUGIN_NAME must be set"

		self.__actions: list[Action] = list()
		self.logger: binaryninja.Logger = binaryninja.log.Logger(
			0, f"{_PLUGIN_NAME}.{self.__class__.__name__}"
		)

	def register(self, action: Action) -> None:
		self.logger.log_info(f"Registering {action.short_name} action")

		if not action.display_name or not action.description:
			self.logger.log_error(
				"Display name and description must be filled for action to be registered,"
				f"missing for {action.short_name}"
			)
			return

		self.__actions.append(action)
		action.register()

	def finalize(self) -> None:
		raise NotImplementedError


def init_plugin_tools(name: str):
	global _PLUGIN_NAME
	_PLUGIN_NAME = name

	global _bn_action_manager
	_bn_action_manager = ActionManager()

	binaryninja.log.Logger(0, name)


def get_action_manager() -> ActionManager:
	global _bn_action_manager
	return _bn_action_manager
