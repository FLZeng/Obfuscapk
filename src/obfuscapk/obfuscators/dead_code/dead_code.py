#!/usr/bin/env python3

import logging
import re

from obfuscapk import obfuscator_category
from obfuscapk import util
from obfuscapk.obfuscation import Obfuscation


class DeadCode(obfuscator_category.ICodeObfuscator):
    def __init__(self):
        self.logger = logging.getLogger(
            "{0}.{1}".format(__name__, self.__class__.__name__)
        )
        super().__init__()

    def count_regs(self, codes):
        regv_count = 0
        regp_count = 0
        regv_pattern = re.compile(r"\W*v(\d+)\W+")
        regp_pattern = re.compile(r"\W*p(\d+)\W+")

        matches = regv_pattern.findall(codes)
        for match in matches:
            idx = int(match)
            if (idx + 1) > regv_count:
                regv_count = idx + 1

        matches = regp_pattern.findall(codes)
        for match in matches:
            idx = int(match)
            if (idx + 1) > regp_count:
                regp_count = idx + 1

        return regv_count, regp_count

    def obfuscate_method_block(self, block):
        method_block = []

        pattern = re.compile(r"\s+(?P<op_code>\S+)")
        op_codes = util.get_dead_code_valid_op_codes()

        codes = ''.join(block)
        regv_count, regp_count = self.count_regs(codes)

        locals_count = 0
        last_reg = 'v0'

        for line in block:

            # Skip empty line
            if line.isspace():
                # Append original instruction.
                method_block.append(line)
                continue

            # Check if this line contains an .locals annotation
            match = util.locals_pattern.match(line)
            if match:
                locals_count = int(match.group("local_count"))
                if (
                        locals_count <= 0
                        or locals_count < regv_count
                        or (locals_count + regp_count) >= 15
                ):
                    locals_count = 0
                else:
                    last_reg = 'v' + str(locals_count)
                    line = line.replace(str(locals_count), str(locals_count + 1))

            # Append original instruction.
            method_block.append(line)

            if locals_count <= 0:
                continue

            dice = util.get_random_int(0, 100)
            const_val = dice % 2

            # Check if this line contains an op code at the beginning
            # of the string.
            match = pattern.match(line)
            if (dice > 33) and match:
                op_code = match.group("op_code")
                # If this is a valid op code, randomly insert a dead code
                # after it.
                if op_code in op_codes:
                    method_block.append("\n    const/4 %s, %#x\n"
                                        % (last_reg, const_val))

        return method_block

    def obfuscate(self, obfuscation_info: Obfuscation):
        self.logger.info('Running "{0}" obfuscator'.format(self.__class__.__name__))

        try:
            for smali_file in util.show_list_progress(
                obfuscation_info.get_smali_files(),
                interactive=obfuscation_info.interactive,
                description='Inserting dead codes in smali files',
            ):
                self.logger.debug(
                    'Inserting dead codes in file "{0}"'.format(smali_file)
                )
                with util.inplace_edit_file(smali_file) as (in_file, out_file):

                    editing_method = False
                    method_block = []

                    for line in in_file:

                        if (
                                line.startswith(".method ")
                                and " abstract " not in line
                                and " native " not in line
                                and not editing_method
                        ):
                            # Entering method.
                            editing_method = True
                            out_file.write(line)

                        elif line.startswith(".end method") and editing_method:
                            # Exiting method.
                            editing_method = False
                            method_block = self.obfuscate_method_block(method_block)
                            method_block.append(line)
                            out_file.write(''.join(method_block))
                            method_block = []

                        elif editing_method:
                            # Inside method.
                            method_block.append(line)

                        else:
                            out_file.write(line)

        except Exception as e:
            self.logger.error(
                'Error during execution of "{0}" obfuscator: {1}'.format(
                    self.__class__.__name__, e
                )
            )
            raise

        finally:
            obfuscation_info.used_obfuscators.append(self.__class__.__name__)
