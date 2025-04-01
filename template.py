from dataclasses import dataclass
from typing import List, Dict
from texttable import Texttable
from collections import Counter

from microschc.binary import Buffer
from microschc.parser import PacketParser
from microschc.rfc8724 import FieldDescriptor, PacketDescriptor


@dataclass
class TemplateField:
    id: str
    values: Counter


class Template:
    
    @classmethod
    def find_templates(cls, packets:List[Buffer], parser: PacketParser) -> List['Template']:
        templates_dict: Dict[int, Template] = {}
        templates: List[Template] = []

        for packet in packets:
            packet_descriptor: PacketDescriptor = parser.parse(packet)
            field_descriptors: Dict[int, FieldDescriptor] = {position: field_descriptor for position, field_descriptor in enumerate(packet_descriptor.fields)}
            template: Template = Template(packet_descriptor)

            if hash(template) in templates_dict.keys():
                template = templates_dict[hash(template)]
            else:
                templates_dict[hash(template)] = template
            
            template.add(packet_descriptor)

        for template in templates_dict.values():
            templates.append(template)
        templates = sorted(templates, key= lambda t: len(t.packet_descriptors), reverse=True)
        
        for id, template in enumerate(templates):
            template.id = id

        return templates
    
    def __init__(self, packet_descriptor, id=None):
        
        self.fields:Dict[int, TemplateField] = {}
        self.packet_descriptors = [packet_descriptor]
        
        field_descriptors: Dict[int, FieldDescriptor] = {position: field_descriptor for position, field_descriptor in enumerate(packet_descriptor.fields)}
        
        for i, fd in field_descriptors.items():
            try:
                fid: str = f'{i}-{fd.id.value}'
            except AttributeError:
                fid: str = f'{i}-{fd.id}'
            template_field:TemplateField = TemplateField(id=fid, values=Counter([fd.value]))
            self.fields[i] = template_field
            
    def add(self, packet_descriptor: PacketDescriptor):
        field_descriptors: Dict[int, FieldDescriptor] = {position: field_descriptor for position, field_descriptor in enumerate(packet_descriptor.fields)}
        for i, fd in field_descriptors.items():
            self.fields[i].values.update([fd.value])

    def __eq__(self, other) -> bool:
        return hash(self) == hash(other)

    def __hash__(self) -> int:
        return hash("|".join([template_field.id for template_field in self.fields.values()]))
    
    def __repr__(self) -> str:
        # fields: str = "|".join(f"{position}:{field_descriptor.id.value}" for position, field_descriptor in self.field_descriptors.items())
        return f"id:{self.id} packets: {len(self.packet_descriptors)} fields: {len(self.fields)}"
    
    
def template_as_asciitable(template: Template, max_width:int=256) -> str:
    """
    returns a multiline string representation of a template to print to the console.
    """
    table = Texttable(max_width=max_width)
    rows = [
        ['field ID', 'length']
    ]
    for tf in template.fields.values():
        values_count: int = len(tf.values.most_common())
        unique_lengths: set = {len(value) for value in tf.values.keys()}
        lengths: str = ", ".join([f'{l}' for l in unique_lengths])
        values_column: str = f"{values_count} value{'s' if values_count > 1 else ''} of size{'s' if values_count > 1 else ''}: ({lengths})\n"+"\n".join([f"{value}: {count}" for value, count in tf.values.most_common(n=10)])
        if values_count > 10:
            values_column += '\n...'
        row = [f"{tf.id}", values_column]
        rows.append(row)
    table.add_rows(
        rows=rows
    )
    return table.draw()