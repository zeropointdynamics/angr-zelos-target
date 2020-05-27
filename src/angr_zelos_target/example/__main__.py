import os

import angr
import claripy

from angr.exploration_techniques import Symbion

from angr_zelos_target import ZelosConcreteTarget


CONFIG_DECISION = 0x400AF3
DROP_STAGE2_V2 = 0x400BB6
BINARY_END = 0x0065310D


def main():
    # Create project with zelos `concrete_target`
    print(f">> tutorial script: {os.path.realpath(__file__)}")
    try:
        zelos_target = ZelosConcreteTarget()
    except ConnectionRefusedError as e:
        print(e)
        filename = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "not_packed_elf64"
        )
        print(
            "Ensure the zdbserver is running in the zelos environment, e.g.:\n"
            + f"    (zelos) $ python -m zelos.zdbserver {filename}"
        )
        return
    project = angr.Project(
        zelos_target.filepath,
        concrete_target=zelos_target,
        use_sim_procedures=True,
    )
    entry_state = project.factory.entry_state()
    simgr = project.factory.simgr(entry_state)
    print(f"[0] Created angr_zelos project for {filename}")

    # Reach the first decision point
    simgr.use_technique(Symbion(find=[CONFIG_DECISION]))
    exploration = simgr.run()
    new_concrete_state = exploration.stashes["found"][0]
    print("[1] Got to decision point concretely.")

    # Make rbp-0xc0 (malware config variable) symbolic within angr
    arg0 = claripy.BVS("arg0", 8 * 32)
    symbolic_buffer_address = new_concrete_state.regs.rbp - 0xC0
    new_concrete_state.memory.store(symbolic_buffer_address, arg0)

    # Symbolic execution to solve value of arg0 going down chosen path
    print(f"[2] Symbolically finding second stage @ 0x{DROP_STAGE2_V2:x}")
    simgr = project.factory.simgr(new_concrete_state)
    exploration = simgr.explore(find=DROP_STAGE2_V2, avoid=[])
    new_symbolic_state = exploration.stashes["found"][0]

    # Write discovered arg0 value into concrete memory and continue.
    print(f"[3] Executing concretely until exit @ 0x{BINARY_END:x}")
    simgr = project.factory.simgr(new_symbolic_state)
    mem = [(symbolic_buffer_address, arg0)]
    simgr.use_technique(Symbion(find=[BINARY_END], memory_concretize=mem))
    exploration = simgr.run()
    new_concrete_state = exploration.stashes["found"][0]

    print("[4] DONE.")


if __name__ == "__main__":
    main()
