import "pe"

rule adware_trojan_1 {
   meta:
      hash = "8f0221c5b751fd19c284e344036f5635"
      imphash = "7660bc80e4b34737f0399fa55a8a649e"
   
   strings:
      $s1 = "gogle.com" fullword wide
      $s2 = "\\ntservertemp.ini" fullword wide
      $s3 = "n/sv3/Log/logData.php" fullword wide
      $s4 = "check=md5gmgglbr" fullword ascii
      $s5 = "\\ntserver.ini" fullword wide
      $s6 = "service.game" fullword wide
  
    
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( 3 of ($s*) ) )
}

rule adware_trojan_2 {
	meta:
      hash = "11C11C3E3B119574F5A66BE15AD3124F"
      imphash = "b86e9275759e9960ac457a686ea95561"
   
   strings:
      $s1 = "Mozilla/4.0 (compatible; %s; %s; Rising)" fullword wide
      $s2 = "sservice.gamegogle.com" fullword wide
      $s3 = "dmscoree.dll" fullword wide
      $s4 = "te.exe" fullword wide
      $s5 = "*NanJing WanJuan Info Technology Co. , Ltd.0" fullword ascii
      $s7 = ".?AVCHttpDownload@net@@" fullword ascii
      
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and ( 3 of ($s*) ) 
}

rule adware_trojan_imphashes {
	condition:
		pe.imphash() == "7660bc80e4b34737f0399fa55a8a649e" or
		pe.imphash() == "b86e9275759e9960ac457a686ea95561"
}
