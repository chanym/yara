rule andro_entry_opcode {
        
        condition:
            uint32(57620) == 0x00503DE8 and 
            uint32(57624) == 0xFE16E900 and 
            filesize > 60000000 and
            filesize < 110000000
}


rule isPE {
   
    condition:
        uint16(0) == 0x5A4D and
        uint16(60) == 0x00E8 and
        filesize > 60000000 and
        filesize < 110000000
}
