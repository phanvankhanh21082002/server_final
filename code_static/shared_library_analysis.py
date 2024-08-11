import os
import sys
import shutil
import subprocess
import json
import lief

# Constants for security checks
NA = 'Not Applicable'
NO_RELRO = 'No RELRO'
PARTIAL_RELRO = 'Partial RELRO'
FULL_RELRO = 'Full RELRO'
INFO = 'info'
WARNING = 'warning'
HIGH = 'high'

def nm_is_debug_symbol_stripped(elf_file):
    """Check if debug symbols are stripped using OS utility."""
    out = subprocess.check_output(
        [shutil.which('nm'), '--debug-syms', elf_file],
        stderr=subprocess.STDOUT)
    return b'no debug symbols' in out

class ELFChecksec:
    def __init__(self, elf_path, so_rel):
        self.elf_path = elf_path
        self.elf_rel = so_rel
        self.elf = lief.parse(self.elf_path)

    def checksec(self):
        """Perform security checks on the ELF file and return the results."""
        elf_dict = {}
        elf_dict['name'] = self.elf_rel

        if not self.is_elf(self.elf_path):
            return
        
        # Check for NX (No-eXecute) protection
        is_nx = self.is_nx()
        if is_nx:
            severity = INFO
        else:
            severity = HIGH
        elf_dict['nx'] = {
            'is_nx': is_nx,
            'severity': severity,
        }

        # Check for Stack Canary protection
        has_canary = self.has_canary()
        if has_canary:
            severity = INFO
        else:
            severity = HIGH
        elf_dict['stack_canary'] = {
            'has_canary': has_canary,
            'severity': severity,
        }

        # Check for RELRO (Relocation Read-Only) protection
        relro = self.relro()
        if relro == NA:
            severity = INFO
        elif relro == FULL_RELRO:
            severity = INFO
        elif relro == PARTIAL_RELRO:
            severity = WARNING
        else:
            severity = HIGH
        elf_dict['relocation_readonly'] = {
            'relro': relro,
            'severity': severity,
        }

        # Check for RPATH (Runtime Library Search Path)
        rpath = self.rpath()
        if rpath:
            severity = HIGH
        else:
            severity = INFO
        elf_dict['rpath'] = {
            'rpath': rpath,
            'severity': severity,
        }

        # Check for RUNPATH (Dynamic Linker Search Path)
        runpath = self.runpath()
        if runpath:
            severity = HIGH
        else:
            severity = INFO
        elf_dict['runpath'] = {
            'runpath': runpath,
            'severity': severity,
        }

        # Check for Fortified Functions
        fortified_functions = self.fortify()
        if fortified_functions:
            severity = INFO
        else:
            if self.is_dart():
                severity = INFO
            else:
                severity = WARNING
        elf_dict['fortify'] = {
            'is_fortified': bool(fortified_functions),
            'severity': severity,
        }

        # Check if Symbols are Stripped
        is_stripped = self.is_symbols_stripped()
        if is_stripped:
            severity = INFO
        else:
            severity = WARNING
        elf_dict['symbol'] = {
            'is_stripped': is_stripped,
            'severity': severity,
        }
        return elf_dict

    def is_elf(self, elf_path):
        """Check if the file is an ELF binary."""
        return lief.is_elf(elf_path)

    def is_nx(self):
        """Check if NX (No-eXecute) bit is set."""
        return self.elf.has_nx

    def is_dart(self):
        """Check if the binary is a Dart/Flutter library."""
        dart = ('_kDartVmSnapshotInstructions', 'Dart_Cleanup')
        if any(i in self.strings() for i in dart):
            return True
        for symbol in dart:
            try:
                if self.elf.get_symbol(symbol):
                    return True
            except Exception:
                pass
        return False

    def has_canary(self):
        """Check if the binary has Stack Canary protection."""
        if self.is_dart():
            return True
        for symbol in ('__stack_chk_fail', '__intel_security_cookie'):
            try:
                if self.elf.get_symbol(symbol):
                    return True
            except Exception:
                pass
        return False

    def relro(self):
        """Check the type of RELRO protection."""
        try:
            gnu_relro = lief.ELF.SEGMENT_TYPES.GNU_RELRO
            bind_now_flag = lief.ELF.DYNAMIC_FLAGS.BIND_NOW
            flags_tag = lief.ELF.DYNAMIC_TAGS.FLAGS
            flags1_tag = lief.ELF.DYNAMIC_TAGS.FLAGS_1.NOW

            if self.is_dart():
                return NA

            if not self.elf.get(gnu_relro):
                return NO_RELRO

            flags = self.elf.get(flags_tag)
            bind_now = flags and bind_now_flag in flags

            flags1 = self.elf.get(flags1_tag)
            now = flags1 and flags1_tag in flags1

            if bind_now or now:
                return FULL_RELRO
            else:
                return PARTIAL_RELRO
        except Exception:
            return NO_RELRO

    def rpath(self):
        """Check if RPATH is set."""
        try:
            rpath = lief.ELF.DYNAMIC_TAGS.RPATH
            return self.elf.get(rpath)
        except Exception:
            return False

    def runpath(self):
        """Check if RUNPATH is set."""
        try:
            runpath = lief.ELF.DYNAMIC_TAGS.RUNPATH
            return self.elf.get(runpath)
        except Exception:
            return False

    def is_symbols_stripped(self):
        """Check if symbols are stripped from the binary."""
        try:
            return nm_is_debug_symbol_stripped(self.elf_path)
        except Exception:
            for i in self.elf.static_symbols:
                if i:
                    return False
            return True

    def fortify(self):
        """Check for fortified functions in the binary."""
        fortified_funcs = []
        for function in self.elf.symbols:
            if isinstance(function.name, bytes):
                try:
                    function_name = function.name.decode('utf-8')
                except UnicodeDecodeError:
                    function_name = function.name.decode('utf-8', 'replace')
            else:
                function_name = function.name
            if function_name.endswith('_chk'):
                fortified_funcs.append(function.name)
        return fortified_funcs

    def strings(self):
        """Retrieve all strings from the binary."""
        normalized = set()
        try:
            elf_strings = self.elf.strings
        except Exception:
            elf_strings = None
        if not elf_strings:
            elf_strings = strings_on_binary(self.elf_path)
        for i in elf_strings:
            if isinstance(i, bytes):
                continue
            normalized.add(i)
        return list(normalized)

    def get_symbols(self):
        """Retrieve all symbols from the binary."""
        symbols = []
        try:
            for i in self.elf.symbols:
                symbols.append(i.name)
        except Exception:
            pass
        return symbols

def find_so_files(directory):
    """Find all .so files in the given directory."""
    so_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".so"):
                so_files.append(os.path.join(root, file))
    return so_files

def main():
    """Main function to analyze all .so files in the specified directory."""
    so_directory = sys.argv[1]
    so_files = find_so_files(so_directory)
    results = []
    for so_file in so_files:
        elf_checker = ELFChecksec(so_file, os.path.relpath(so_file, so_directory))
        analysis = elf_checker.checksec()
        if analysis:
            results.append(analysis)
    
    # Print results as JSON
    print(json.dumps(results))

if __name__ == "__main__":
    main()
