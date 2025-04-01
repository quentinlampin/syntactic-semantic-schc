from typing import List

from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket, Block

from microschc.binary import Buffer

ETHERNET_HEADER_LENGTH = 14


def packet_filter(block: Block) -> bool:
    """Filter for PCAPng EnhancedPacket.
    
    Args:
        block (Block): PCAPng block
        
    Returns:
        bool: True is block is an EnhancedPacket
    """
    return isinstance(block, EnhancedPacket)


def packets_list(filepath: str, header_offset:int = ETHERNET_HEADER_LENGTH) -> List[Buffer]:
    """Parses a PCAPng file and returns a list of packet buffers.

    Args:
        filepath (str): filepath of the dataset. The expected dataset format is PCAPng
        header_offset (14): location of the first byte to parse (default is 14, skip Ethernet header)

    Returns:
        List[Buffer]: List of packet buffers
    """
    
    with open(filepath, 'rb') as fp:
            # retrieve all SCHC context packets
            scanner: FileScanner = FileScanner(fp) 
            packets:List[Buffer] = [
                Buffer(
                    content=p.packet_data[header_offset:],
                    length=(p.packet_len-header_offset)*8
                ) for p in filter(packet_filter, scanner)
            ]
    return packets