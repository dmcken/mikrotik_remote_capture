'''Clean a mikrotik / TZSP capture file.

'''

# System imports
import argparse
import logging

# Scapy imports
import scapy.all
import scapy.contrib.tzsp

logger = logging.getLogger(__name__)

def parse_argument() -> argparse.Namespace:
    """Parse cli arguments.

    Returns:
        argparse.Namespace: The parsed arguments.
    """
    parser = argparse.ArgumentParser(
                    prog='ProgramName',
                    description='What the program does',
                    epilog='Text at the bottom of help')

    parser.add_argument('input')
    parser.add_argument('output')

    parser.add_argument('-p','--port', default=37008, type=int)

    args = parser.parse_args()

    # Setup logging
    basic_format = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(
            encoding='utf-8',
            level=logging.INFO,
            format=basic_format,
    )

    return args

def main() -> None:
    '''Main'''
    args = parse_argument()

    # scapy.all.rdpcap or scapy.all.PcapReader

    # Bind the decoding UDP port.
    # bind_layers(UDP, TZSP, sport=TZSP_PORT_DEFAULT)
    # bind_layers(UDP, TZSP, dport=TZSP_PORT_DEFAULT)
    scapy.all.bind_layers(
        scapy.all.UDP,
        scapy.contrib.tzsp.TZSP,
        dport=args.port,
    )

    modulus = 100_000

    with scapy.all.PcapNgReader(args.input) as cap_file, \
        scapy.all.PcapNgWriter(args.output) as output_file:
        count = 0
        for curr_pkt in cap_file:
            cleaned = curr_pkt[scapy.contrib.tzsp.TZSPTagEnd].payload
            output_file.write(cleaned)
            count += 1
            if count % modulus == 0:
                logger.info(f"{count:,}")

    logger.info(f"Completed processing {count:,} packets")

if __name__ == '__main__':
    main()
