from microschc.rfc8724 import RuleDescriptor, FieldDescriptor, PacketDescriptor, RuleNature
from microschc.rfc8724 import MatchingOperator as MO, CompressionDecompressionAction as CDA
from microschc.rfc8724 import MatchMapping
from dataclasses import dataclass
from typing import List, Dict
from texttable import Texttable
from collections import Counter

from microschc.binary import Buffer
from microschc.parser import PacketParser

def rule_descriptor_as_ascii_table(rule_descriptor: RuleDescriptor, max_width:int=256) -> str:
    """
    returns a multiline string representation of a rule to print to the console.
    """
    mo_to_short_str: Dict[str,str] = {MO.EQUAL:'eq', MO.IGNORE:'ig', MO.MATCH_MAPPING:'ma', MO.MSB:'ms'}
    cda_to_short_str: Dict[str,str] = {CDA.NOT_SENT:'ns', CDA.VALUE_SENT:'vs', CDA.MAPPING_SENT:'ma', CDA.LSB:'ls', CDA.COMPUTE:'co'}
    table = Texttable(max_width=max_width)
    if rule_descriptor.nature == RuleNature.COMPRESSION:
        rows = [
            ['FID', 'LEN', 'FD', 'MO/CDA', 'TV']
        ]
        for f_pos, fd in enumerate(rule_descriptor.field_descriptors):
            if fd.compression_decompression_action == CDA.MAPPING_SENT:
                target_value_str = ""
                target_value: MatchMapping = fd.target_value
                for k,v in target_value.reverse.items():
                    target_value_str += f"{k}: {v}\n"
                row = [f"{f_pos}-{fd.id}", f"{fd.length}", f"{fd.direction}", f"{mo_to_short_str[fd.matching_operator]}/{cda_to_short_str[fd.compression_decompression_action]}",  target_value_str]
            else:
                row = [f"{f_pos}-{fd.id}", f"{fd.length}", f"{fd.direction}", f"{mo_to_short_str[fd.matching_operator]}/{cda_to_short_str[fd.compression_decompression_action]}",  fd.target_value]
            rows.append(row)
        table.add_rows(
            rows=rows
        )
    elif rule_descriptor.nature == RuleNature.NO_COMPRESSION:
        rows = [['NO COMPRESSION']]
        table.add_rows(rows=rows)

    return table.draw()