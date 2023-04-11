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

    def obfuscate(self, obfuscation_info: Obfuscation):
        self.logger.info('Running "{0}" obfuscator'.format(self.__class__.__name__))

        try:
            op_codes = util.get_dead_code_valid_op_codes()
            pattern = re.compile(r"\s+(?P<op_code>\S+)")

            for smali_file in util.show_list_progress(
                obfuscation_info.get_smali_files(),
                interactive=obfuscation_info.interactive,
                description='Inserting dead codes in smali files',
            ):
                self.logger.debug(
                    'Inserting dead codes in file "{0}"'.format(smali_file)
                )
                with util.inplace_edit_file(smali_file) as (in_file, out_file):
                    locals_count = 0
                    last_reg = 'v0'

                    for line in in_file:

                        # Skip empty line
                        if line.isspace():
                            # Print original instruction.
                            out_file.write(line)
                            continue

                        # Check if this line contains an .locals annotation
                        match = util.locals_pattern.match(line)
                        if match:
                            locals_count = int(match.group("local_count"))
                            if 0 < locals_count < 15:
                                last_reg = 'v' + str(locals_count)
                                line = line.replace(str(locals_count), str(locals_count+1))
                            else:
                                locals_count = 0

                        # Print original instruction.
                        out_file.write(line)

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
                                out_file.write("\n    const/4 %s, %#x"
                                               % (last_reg, const_val))

        except Exception as e:
            self.logger.error(
                'Error during execution of "{0}" obfuscator: {1}'.format(
                    self.__class__.__name__, e
                )
            )
            raise

        finally:
            obfuscation_info.used_obfuscators.append(self.__class__.__name__)
