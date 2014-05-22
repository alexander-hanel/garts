'''
Name:
    garts.py (Get all referenced text strings)
Version:
    1.0 
Date:
    2014/05/21
Author:
    alexander<dot>hanel<at>gmail<dot>com
Description:
    garts.py is a simple string viewer for IDA. It will iterate through
    all known functions, look for possible string refercences and then
    print them. This is super helpful for dealing with strings in Delphi
    executables, finding missed strings or having the exact location of
    where the string is being used.

    Example Output 
    Address      String
    0x1a701045                  <- new line char. Not the best starting example..         
    0x1a7010bd   #command
    0x1a701199   SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    0x1a7011be   govShell

    Xref Example
    .text:1A7010BD                 push    offset aCommand ; "#command"
    .text:1A7010C2                 lea     eax, [ebp+var_110]
    ....
    .text:1A701199                 push    offset SubKey   ; "SOFTWARE\\Microsoft\\Windows\\CurrentVersi"...
    .text:1A70119E                 push    80000001h       ; hKey
    .text:1A7011A3                 call    ds:RegOpenKeyA

    The script also calls the helpful idautils.strings and then adds all
    the found strings to the viewer window.

    Any ideas, comments, bugs, etc please send me an email or ping me on twitter @nullandnull. Cheers. 
'''

import idautils
class Viewer(idaapi.simplecustviewer_t):
    # modified version of http://dvlabs.tippingpoint.com/blog/2011/05/11/mindshare-extending-ida-custviews
    def __init__(self, data):
        self.fourccs = data
        self.Create()
        self.Show()

    def Create(self):
        title = "A Better String Viewer"
        idaapi.simplecustviewer_t.Create(self, title)
        c = "%s %11s" % ("Address", "String")
        comment = idaapi.COLSTR(c, idaapi.SCOLOR_BINPREF)
        self.AddLine(comment)
        for item in self.fourccs:
            addy = item[0]
            string_d = item[1]
            address_element = idaapi.COLSTR("0x%08x " % addy, idaapi.SCOLOR_REG)
            str_element = idaapi.COLSTR("%-1s" % string_d, idaapi.SCOLOR_REG)
            line = address_element + "  " +  str_element
            self.AddLine(line)
        return True

    def OnDblClick(self, something):
        value = self.GetCurrentWord()
        if value[:2] == '0x':
            Jump(int(value, 16))
        return True

    def OnHint(self, lineno):
        if lineno < 2: return False
        else: lineno -= 2
        line = self.GetCurrentWord()
        if line == None: return False
        if "0x" not in line: return False
        # skip COLSTR formatting, find address
        addy = int(line, 16)
        disasm = idaapi.COLSTR(GetDisasm(addy) + "\n", idaapi.SCOLOR_DREF)
        return (1, disasm)


def enumerate_strings():
    display = []
    # interate through all functions 
    for func in idautils.Functions():
        flags = GetFunctionFlags(func)
        # ignore library code 
        if flags & FUNC_LIB or flags & FUNC_THUNK:
            continue
        # get a list of the addresses in the function. Using a range of < or >
        # if flawed when the code is obfuscated. 
        dism_addr = list(FuncItems(func))
        # for each instruction in the function 
        for line in dism_addr:
            temp = None
            val_addr = 0
            if GetOpType(line,0) == 5:
                val_addr = GetOperandValue(line,0)
                temp = GetString(val_addr, -1)
            elif GetOpType(line,1) == 5:
                val_addr = GetOperandValue(line,1)
                temp = GetString(val_addr, -1)
            if temp:
                # in testing isCode() failed to accurately detect if address was code
                # decided to try something a little more generic 
                if val_addr not in dism_addr and GetFunctionName(val_addr) == '':
                    if GetStringType(val_addr) == 3:
                        temp = GetString(val_addr, -1, ASCSTR_UNICODE)
                    display.append((line, temp))

    # Get the strings already found
    # https://www.hex-rays.com/products/ida/support/idapython_docs/idautils.Strings-class.html
    s = idautils.Strings(False)
    s.setup(strtypes=Strings.STR_UNICODE | Strings.STR_C)
    for i, v in enumerate(s):
        if v is None:
            pass
        else:
            display.append((v.ea, str(v)))

    sorted_display = sorted(display, key=lambda tup:tup[0])
    return sorted_display


if __name__ == "__main__":
    ok = enumerate_strings()
    Viewer(ok)
