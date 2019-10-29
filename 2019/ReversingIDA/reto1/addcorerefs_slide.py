__author__ = 'Oscar Martín Vicente'

import idautils
import idaapi

JMPS = [idaapi.NN_jmp, idaapi.NN_jmpfi, idaapi.NN_jmpni]
CALLS = [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]

for func in idautils.Functions():
    flags = idc.get_func_attr(func, FUNCATTR_FLAGS)
    if flags & FUNC_LIB or flags & FUNC_THUNK:
        continue
    dism_addr = list(idautils.FuncItems(func))
    
    for ea in dism_addr:
        idaapi.decode_insn(ea)
        if idaapi.cmd.itype in JMPS or idaapi.cmd.itype in CALLS:
            if idc.get_operand_type(ea, 0) == 2:
                iat_offset_addr = idc.get_operand_value(ea, 0)
                idc.AddCodeXref(ea, iat_offset_addr, idc.XREF_USER | idc.fl_CN)
                print "Adding xref for 0x%x %s to 0x%x" % (ea, idc.generate_disasm_line(ea, 0), iat_offset_addr)
            elif idc.get_operand_type(ea, 0) == 1:
                disasm = idc.generate_disasm_line(ea, 0)
                parts = disasm.split(";")
                if len(parts) == 2:
                    funcName = parts[1].strip()
                    iat_offset_addr = idc.get_name_ea_simple(funcName)
                    if iat_offset_addr != idc.BADADDR:
                        idc.AddCodeXref(ea, iat_offset_addr, idc.XREF_USER | idc.fl_CN)
                        print "Adding xref for 0x%x %s to 0x%x" % (ea, idc.generate_disasm_line(ea, 0), iat_offset_addr)
            else:
                print "Call or Jump instruction does not need to be xref'ed: %s" % idc.generate_disasm_line(ea, 0)

