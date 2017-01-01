import "pe"

/*
      text = "812AC176DAFCD7C2BDD4FE8F79FCA3A9"
      rdata = "26A301E1AE63F584717C3A28DAC6C0BF"
      data = "25B7235D58C6EB39E4BCEBC011C2DDEE"
      rsrc = "85DD056436B3C88DE3352DC085192816"
      reloc = "48BBA499E48915780286F6D5591B2122"
      OriginalFilename = "Birds.dll"
*/

rule Wimmie_Addon {
   meta:
      desc = "Beside '\x00ScriptMan', more specific strings are added on from yarGen specific string result"
      hash1 = "c9a0b4a65c9b9704a864cf25df931aaf"
      

   strings:
      $s1 = "\x00ScriptMan"
      $s2 = "GrayPartridge.dll" fullword ascii
      $s3 = "HeadLoginView" fullword ascii
      $s4 = "http://tempuri.org/GetNumberT" fullword ascii
      $s5 = "RosyStarling.dll" fullword ascii
      $s6 = "RuppellsVulture.dll" fullword ascii
      $s7 = "MacQueensBustard.dll" fullword ascii
      $s8 = "Araponga.dll" fullword ascii
      $s9 = "BrownKiwi.dll" fullword wide
      $s10 = "BlackSwan.dll" fullword ascii
      $s11 = "RedKite.dll" fullword ascii
      $s12 = "Birds.dll" fullword wide
      $s13 = "Emu.dll" fullword ascii
      $s14 = "Kagu.dll" fullword ascii
      $s15 = "D:\\vin\\BrownKiwi\\obj\\Release\\BrownKiwi.pdb" fullword ascii
      $s16 = "\\zlibwapi.dll" fullword wide

   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 5 of ($s*) ) )
}

rule Wimmie_Addon_AntiDebug{
    condition:
         pe.imports("KERNEL32.DLL", "GetTickCount") and
         pe.imports("KERNEL32.DLL", "IsDebuggerPresent")
}

rule Wimmie_Addon_Export{
    condition:
	 pe.exports("Fly")
}
		
