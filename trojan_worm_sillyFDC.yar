import "pe"

/*
Information on the Trojan Worm SillyFDC
    Num_of_sections = 3
    imported_lib = msvbvm60.dll
    symbol_from_lib = _vbaWriteFile, 593, 594, DllFunctionCall, 600, 716,100
    md5 = 99577A749D880A235464CA4A8A9D2B5E
    OriginalFilename = RS Caparros Payroll.exe
    imphash = 0dc1eb84a5aed311d81e373106d02c9d
    .text = FB7C9B3289030E2AC7C979803AA86CA5
    .data = 620F0B67A91F7F74151BC5BE745B7110
    .rsrc = 8C0A9B089B3C27AD584EC96212C447C4
    characteristic = PE32 and executable using folder icon as icon
    antiDebug on SEH for vba was found     
*/

rule SillyFDC_strings_found {
   
   strings:
      $x1 = "C:\\temp.exe" nocase fullword wide 
      $x2 = "c:\\payload.exe" nocase fullword ascii
      $s1 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" nocase fullword ascii
      $s2 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" nocase fullword wide
      $s3 = "c:\\loadme.txt" nocase fullword wide
      $s4 = "Converting exe to txt c:\\loadme.txt" nocase fullword wide
      $s5 = "VBA6.DLL" nocase fullword ascii
      $s6 = "http://198.173.124.107/setup.html" fullword wide
      $s7 = "getkeyval" fullword ascii
      $s8 = "RS Caparros Payroll.exe" nocase fullword wide
   
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) and 3 of ($s*) ) 

}

rule SillyFDC_imphash{
     condition:
         pe.imphash() == "0dc1eb84a5aed311d81e373106d02c9d"
}


rule SillyFDC_imports_and_functions{
    condition:
        pe.imports("msvbvm60.dll", "DllFunctionCall")
}
