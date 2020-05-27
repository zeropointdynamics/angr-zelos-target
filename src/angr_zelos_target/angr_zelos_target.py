# Copyright (C) 2020 Zeropoint Dynamics

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
# ======================================================================

import logging
import xmlrpc

import angr
import claripy
from angr_targets.concrete import ConcreteTarget
from angr.errors import (
    SimConcreteMemoryError,
    SimConcreteRegisterError,
    SimConcreteBreakpointError,
)


class ZelosExplorationTechnique(angr.exploration_techniques.Symbion):
    """
    Extension of Symbion exploration technique to include breakpointing
    on syscalls as specified by name.
    """

    def __init__(
        self,
        zelos,
        state,
        find=None,
        syscall_breaks=[],
        memory_concretize=None,
        register_concretize=[],
        timeout=0,
        find_stash="found",
    ):
        # Register syscall breakpoints. Symbion does not support
        # breaking on syscalls, so we assign a fake address to each
        # syscall name to satisfy it's engine when breaking from
        # unexpected addresses.
        self.zelos = zelos
        self.syscall_breaks = {}
        self.syscall_breaks_by_address = {}
        for syscall in syscall_breaks:
            syscall_fake_pc = zelos.set_syscall_breakpoint(
                syscall, temporary=True
            )
            self.syscall_breaks[syscall] = syscall_fake_pc
            self.syscall_breaks_by_address[syscall_fake_pc] = syscall
            if find is None:
                find = []
            find.append(syscall_fake_pc)
        super(ZelosExplorationTechnique, self).__init__(
            find, memory_concretize, register_concretize, timeout, find_stash
        )

    def complete(self, simgr):
        """
        When concrete execution is complete, correct any fake pc used
        for syscall breaking before returning the state.
        """
        completed = super(ZelosExplorationTechnique, self).complete(simgr)
        if completed is True:
            simgr.stashes[self.find_stash][0].syscall = None
            pc = simgr.stashes[self.find_stash][0].regs.pc
            pc = claripy.backends.concrete.convert(pc).value
            if pc in self.syscall_breaks_by_address:
                # This break was caused by a syscall. Fixup PC by
                # changing it from the fake address back to the real
                # address that would be executed immediately after the
                # syscall.
                break_state = self.zelos.break_state()
                real_pc = self.zelos.real_pc
                self.zelos.write_register("pc", real_pc)
                simgr.stashes[self.find_stash][0].regs.pc = claripy.BVV(
                    real_pc, break_state["bits"]
                )
                simgr.stashes[self.find_stash][0].break_state = break_state
                if break_state["syscall"]:
                    simgr.stashes[self.find_stash][0].is_syscall = True
                else:
                    simgr.stashes[self.find_stash][0].is_syscall = False

        return completed


# logging.basicConfig(level=logging.DEBUG)
l = logging.getLogger("angr_targets.zelos")
# l.setLevel(logging.DEBUG)


class ZelosConcreteTarget(ConcreteTarget):
    def __init__(self, server_url="http://localhost:62433"):
        import xmlrpc.client

        self.s = xmlrpc.client.ServerProxy(server_url)
        self._filepath = self.s.get_filepath()
        self.timeout = None
        self.syscall_fake_pc_idx = 0xffffffffffff0000
        self.syscall_fake_pcs = dict()
        self.real_pc = 0
        self._break_state = None

    def exit(self):
        self.s.close()

    def read_memory(self, address, nbytes, **kwargs):
        """
        Reading from memory of the target

        :param int address: The address to read from
        :param int nbytes:  The amount number of bytes to read
        :return:        The memory read
        :rtype: bytes
        :raise angr.errors.ConcreteMemoryError:
        """
        try:
            address = "0x{0:x}".format(address)
            data = self.s.read_memory(address, nbytes)
            return data.data
        except Exception as e:
            msg = (
                "ZelosConcreteTarget can't read_memory @ %s exception %s"
                % (address, e)
            )
            l.debug(msg)
            raise SimConcreteMemoryError(msg)

    def write_memory(self, address, value, **kwargs):
        """
        Writing to memory of the target

        :param int address:   The address to start writing
        :param str value:     The actual value written to memory
        :raise angr.errors.ConcreteMemoryError:
        """
        try:
            address = "0x{0:x}".format(address)
            self.s.write_memory(address, xmlrpc.client.Binary(value))
        except Exception as e:
            msg = (
                "ZelosConcreteTarget can't write_memory @ %s exception %s"
                % (address, e)
            )
            l.debug(msg)
            raise SimConcreteMemoryError(msg)

    def read_register(self, register, **kwargs):
        """'
        Reads a register from the target
        'pc' should be treated according to the architecture (eip,rip)

        :param str register: The name of the register
        :return: int value of the register content
        :rtype int
        :raise angr.errors.ConcreteRegisterError: register doesn't exist
        """
        try:
            value = self.s.read_register(register)
            value = int(value, 16) if value.startswith("0x") else int(value)
            return value
        except Exception as e:
            msg = (
                "ZelosConcreteTarget can't read_register '%s', exception %s"
                % (register, e)
            )
            l.debug(msg)
            raise SimConcreteRegisterError(msg)

    def write_register(self, register, value, **kwargs):
        """
        Writes a register to the target
        'pc' should be treated according to the architecture (eip,rip)

        :param str register:     The name of the register
        :param int value:        int value to be written to register
        :raise angr.errors.ConcreteRegisterError:
        """
        try:
            value = "0x{0:x}".format(value)
            self.s.write_register(register, value)
        except Exception as e:
            msg = (
                "ZelosConcreteTarget can't write_register '%s', exception %s"
                % (register, e)
            )
            l.debug(msg)
            raise SimConcreteRegisterError(msg)

    def set_breakpoint(self, address, **kwargs):
        """
        Inserts a breakpoint

        :param int address: The address at which to set the breakpoint
        :param optional bool hardware: Hardware breakpoint
        :param optional bool temporary:  Tempory breakpoint
        :raise angr.errors.ConcreteBreakpointError:
        """
        l.debug("ZelosConcreteTarget set_breakpoint at %x " % (address))
        try:
            address = "0x{0:x}".format(address)
            self.s.set_breakpoint(address, kwargs.get("temporary", False))
        except Exception as e:
            msg = "ZelosConcreteTarget failed to set_breakpoint at %s: %s" % (
                address,
                e,
            )
            l.debug(msg)
            raise SimConcreteBreakpointError(msg)

    def remove_breakpoint(self, address, **kwargs):
        l.debug("ZelosConcreteTarget remove_breakpoint at %x " % (address))
        try:
            address = "0x{0:x}".format(address)
            self.s.remove_breakpoint(address)
        except Exception as e:
            msg = (
                "ZelosConcreteTarget failed to remove_breakpoint at %s: %s"
                % (address, e)
            )
            l.debug(msg)
            raise SimConcreteBreakpointError(msg)

    def set_watchpoint(self, address, **kwargs):
        """
        Inserts a watchpoint

        :param address: The name of a variable or an address to watch
        :param optional bool write:    Write watchpoint
        :param optional bool read:     Read watchpoint
        :raise angr.errors.ConcreteBreakpointError:
        """
        l.debug("ZelosConcreteTarget set_watchpoint at %x " % (address))
        try:
            address = "0x{0:x}".format(address)
            self.s.set_watchpoint(
                address, kwargs.get("read", True), kwargs.get("write", True)
            )
        except Exception as e:
            msg = "ZelosConcreteTarget failed to set_watchpoint at %s: %s" % (
                address,
                e,
            )
            l.debug(msg)
            raise SimConcreteBreakpointError(msg)

    def remove_watchpoint(self, address, **kwargs):
        l.debug("ZelosConcreteTarget remove_watchpoint at %x " % (address))
        try:
            address = "0x{0:x}".format(address)
            self.s.remove_watchpoint(address)
        except Exception as e:
            msg = (
                "ZelosConcreteTarget failed to remove_watchpoint at %s: %s"
                % (address, e)
            )
            l.debug(msg)
            raise SimConcreteBreakpointError(msg)

    def get_mappings(self):
        class MemoryMap:
            """
            Describing a memory range inside the concrete
            process.
            """

            def __init__(self, start_address, end_address, offset, name):
                self.start_address = start_address
                self.end_address = end_address
                self.offset = offset
                self.name = name

            def __str__(self):
                my_str = (
                    "MemoryMap[start_address: 0x%x | end_address: 0x%x | name: %s"
                    % (self.start_address, self.end_address, self.name)
                )
                return my_str

        l.debug("ZelosConcreteTarget MAPPINGS")
        vmmap = []
        try:
            regions = self.s.get_mappings()
            for region in regions:
                val = region["start_address"]
                start = val = (
                    int(val, 16) if val.startswith("0x") else int(val)
                )
                val = region["end_address"]
                end = val = int(val, 16) if val.startswith("0x") else int(val)
                val = region.get("offset", "0x0")
                offset = val = (
                    int(val, 16) if val.startswith("0x") else int(val)
                )
                vmmap.append(
                    MemoryMap(start, end, offset, region.get("name", "_____"))
                )
        except Exception as e:
            msg = "ZelosConcreteTarget failed to run: %s" % (e)
            l.debug(msg)
        return vmmap

    def run(self):
        """
        Runs until a break condition is encountered. Saves information
        about the break condition at `self.break_state()` in format:

        break_state = {
            'pc': INT,
            'syscall': {
                'name': STR,
                'args': [
                    { 'type': STR, 'name': STR, 'value': INT },
                    ...
                ],
                'retval': INT,
                'retval_register': STR,
            },
            'bits': INT,
        }
        """
        l.debug("ZelosConcreteTarget RUN")
        try:
            break_state = self.s.run()
            l.debug("ZelosConcreteTarget BREAK")

            # Syscall breaking support
            syscall = break_state.get("syscall", None)
            pc = break_state.get(
                "pc", "0x{0:x}".format(self.read_register("pc"))
            )
            self.real_pc = int(pc, 16) if pc.startswith("0x") else int(pc)
            break_state["pc"] = self.real_pc
            l.debug(f"  real_pc=0x{self.real_pc:x} syscall='{syscall}'")

            if syscall is not None and syscall != {}:
                syscall_name = syscall["name"]
                # If we break due to a syscall, fake the PC so Symbion
                # doesn't complain about breaking at a non-breakpoint
                # address. Write the fake address here, but then restore
                # it to the correct value in
                # ZelosExplorationTechnique.complete before returning
                # the user's script.
                fake_pc = self.syscall_fake_pcs.get(syscall_name, None)
                l.debug(f"  fake_pc=0x{fake_pc:x} syscall='{syscall}'")
                if fake_pc is not None:
                    self.write_register("pc", fake_pc)
                # Format syscall args as numbers
                for arg in break_state["syscall"]["args"]:
                    val = arg["value"]
                    arg["value"] = (
                        int(val, 16) if val.startswith("0x") else int(val)
                    )

            self._break_state = break_state

        except Exception as e:
            msg = "ZelosConcreteTarget failed to run: %s" % (e)
            l.debug(msg)

    def stop(self):
        l.debug("ZelosConcreteTarget STOP")
        try:
            self.s.stop()
        except Exception as e:
            msg = "ZelosConcreteTarget failed to stop: " % (e)
            l.debug(msg)

    """
    Zelos-specific Extensions
    """

    def break_state(self):
        return self._break_state

    def set_syscall_breakpoint(self, name, **kwargs):
        """
        Inserts a breakpoint at a specified syscall

        :param str name: The name of a syscall to break at
        :param optional bool temporary: indicates one-off breakpoints
        :raise angr.errors.ConcreteBreakpointError:
        """
        l.debug("ZelosConcreteTarget set_syscall_breakpoint at '%s' " % (name))

        if name in self.syscall_fake_pcs:
            fake_pc = self.syscall_fake_pcs[name]
        else:
            fake_pc = self.syscall_fake_pc_idx
            self.syscall_fake_pc_idx += 1
            self.syscall_fake_pcs[name] = fake_pc

        try:
            self.s.set_syscall_breakpoint(name, kwargs.get("temporary", False))
        except Exception as e:
            msg = (
                "ZelosConcreteTarget failed set_syscall_breakpoint '%s': %s"
                % (name, e)
            )
            l.debug(msg)
            raise SimConcreteBreakpointError(msg)

        return fake_pc

    def remove_syscall_breakpoint(self, name, **kwargs):
        l.debug(
            "ZelosConcreteTarget remove_syscall_breakpoint at '%s' " % (name)
        )
        try:
            self.s.remove_syscall_breakpoint(name)
        except Exception as e:
            msg = (
                "ZelosConcreteTarget failed remove_syscall_breakpoint '%s': %s"
                % (name, e)
            )
            l.debug(msg)
            raise SimConcreteBreakpointError(msg)

    @property
    def filepath(self) -> str:
        return self._filepath
