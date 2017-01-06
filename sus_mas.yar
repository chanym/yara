import "pe"
 
 /*
             MD5                             entropy
 .text      3187a0b1aa73e329aff67b3110066be1 6.261719    
 .rdata     76bee3ec122db15cd0a1581e8d21d54e 4.546591    
 .data      a332667e3348db67ce100f7a00efd42d 2.822140    
 .pdata     9b4887fec6661a7ad3882b48d090e73e 5.126443    
 .rsrc      6592e92c1bed0a0f1147a78eb4a661fd 5.115767    
 .reloc     6590b51d6b1717318132e14ad4778566 3.934557
 
 payload needs to run as a dll using the argument ServiceMain
 example
 rundll32 <payload>, ServiceMain
 */
 
 
 rule suspicious_mas {
     meta:
         md5 = "4b74c872d2929db9b4e926429d12c336"
         imphash = "ec7486f6ba69c264b74568ae5af59b0c"
     
     strings:
         $s1 = "F:\\95\\95-01\\RCE\\bin\\Release\\x64\\mas.pdb" fullword ascii
         $s2 = "MAS.dll" fullword ascii
         $s3 = "Windows Authentication Service (formerly named NTLM, and also referred to as Windows  NT Challenge/Response authentication) is a " ascii 
    
    condition:
         ( uint16(0) == 0x5a4d and filesize < 500KB and ( 2 of ($s*) ) ) and 
         ( pe.exports("ServiceMain") or pe.exports("SvcControl") ) 
 }

rule suspicious_mas_imphash{
     condition:
         pe.imphash() == "ec7486f6ba69c264b74568ae5af59b0c"
 }

