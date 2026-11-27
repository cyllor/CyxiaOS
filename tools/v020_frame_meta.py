"""Match stopped-guest DMA ownership to the linked queues and their devices."""
import re
import struct

from check_elf import symbol
from verify_smp import require


PAGE = 4096
RAM_BASE = 0x40000000
FRAME_ROW = struct.Struct("<IIQQIIII")
PERMANENT_ROW = (0xFFFFFFFF, 4, 0, 0, 0, 0, 0, 0)
QUEUES = {"block": (2, 0), "net_rx": (1, 0), "net_tx": (1, 1), "rng": (4, 0)}


def queue_dma_rows(qmp, image: bytes, raw: bytes, required: set[str]) -> tuple[dict, dict]:
    start = symbol(image, "__sec_n_dma_start")["pa"]
    end = symbol(image, "__sec_n_dma_end")["pa"]
    require(RAM_BASE <= start <= end <= 0x44000000 and start % PAGE == end % PAGE == 0,
            "linked DMA arena is outside reserved RAM")
    layout = []
    for name in QUEUES:
        label = f"V020_DMA_{name.upper()}_QUEUE"
        try:
            location = symbol(image, label)
        except ValueError as error:
            if str(error) != f"missing symbol {label}" or name in required:
                raise
            continue
        pa, size = location["pa"], location["size"]
        require(size == (3 + 2 * 8) * PAGE and pa % PAGE == 0 and start <= pa < pa + size <= end,
                f"invalid linked {name} DMA queue")
        layout.append((pa, pa + size, name))
    cursor = start
    claimed, queues = {}, {}
    for first, last, name in sorted(layout):
        require(first == cursor, "linked DMA queues overlap or leave an unclassified page")
        cursor = last
        begin, finish = ((pa - RAM_BASE) // PAGE for pa in (first, last))
        require(finish * FRAME_ROW.size <= len(raw), "DMA queue outside captured FrameMeta rows")
        records = list(FRAME_ROW.iter_unpack(raw[begin * FRAME_ROW.size:finish * FRAME_ROW.size]))
        if name not in required:
            require(all(record == PERMANENT_ROW for record in records),
                    f"inactive {name} DMA queue was assigned")
            continue
        device, index = QUEUES[name]
        owner = records[0][0]
        offset = owner ^ 0x80000000
        require(offset < 0x200000 and offset & 3 == index, f"invalid {name} DMA queue owner")
        row = (owner, 4, 1, 1, 0, 1, 1, 0)
        require(all(record == row for record in records), f"incomplete {name} DMA queue assignment")
        transport = 0x0a000000 + (offset & ~3)
        # Device ID is read-only and does not select or modify any queue.
        identity = transport + 8
        value = qmp.execute("human-monitor-command", {"command-line": f"xp/1wx {identity:#x}"})
        match = re.fullmatch(r"([\da-fA-F]+): 0x([\da-fA-F]{8})\s*", value)
        require(match is not None and int(match[1], 16) == identity and int(match[2], 16) == device,
                f"{name} DMA owner does not identify the captured VirtIO device")
        for row_index in range(begin, finish):
            claimed[row_index] = row
        queues[name] = {"owner_slot": owner, "device_id": device, "transport_pa": hex(transport),
                        "queue_index": index, "start_pa": hex(first), "pages": finish - begin}
    require(cursor == end and set(queues) == required, "incomplete linked DMA queue inventory")
    if {"net_rx", "net_tx"} <= required:
        require(queues["net_rx"]["transport_pa"] == queues["net_tx"]["transport_pa"],
                "RX and TX DMA owners refer to different transports")
    return claimed, queues
