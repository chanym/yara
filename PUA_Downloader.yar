import "pe"

rule PUA_Downloader {
		meta:
			hash1 = "40e04f0a5d0027571e28ae25006ea3a3"
			hash2 = "a7afa05d61a23570f80cb92a829bc39a"
			hash3 = "29e8102dabfa5f20d046942b3ad93777"
			hash4 = "4ee5dbdec3a61a03fbe79245ff3c6780"
			imphash_for_all_hash = "afcdf79be1557326c854b6e20cb900a7"
			
			
		strings:
			$s1 = "*Unable to get a list of running processes." fullword wide
			$s2 = "PROCESSGETSTATS" fullword wide
       		$s3 = "WINGETPROCESS" fullword wide
       		$s4 = "0Expected a \"=\" operator in assignment statement.*Invalid keyword at the start of this line." fullword wide
       		$s5 = "sScDKIwXVUyxfR0V/dEV+rpVCaf1iWC9+SHNACXRuX0VTL19HRXt0RX5RakJpRWJYL35Ic0BJdG5fRVMvX0dFo3RFfl91+GdF1lHiX/ByDIRVOjcsIA8vNSoc BiQTcQk" ascii
       		$s7 = "SCRIPTNAME" fullword wide
       		$s8 = "/AutoIt3ExecuteScript" fullword wide
       		$s9 = "/AutoIt3ExecuteLine" fullword wide
       		$s10 = "PROCESSSETPRIORITY" fullword wide
       		$s11 = "PROCESSWAITCLOSE" fullword wide
       		$s13 = "PROCESSCLOSE" fullword wide
       		$s14 = "PROCESSWAIT" fullword wide
       		$s15 = "PROCESSEXISTS" fullword wide
       		$s16 = "SHELLEXECUTEWAIT" fullword wide
       		$s17 = "PROCESSORARCH" fullword wide
       		$s18 = "PROCESSLIST" fullword wide
       		
    	condition:
       		( uint16(0) == 0x5a4d and filesize < 3000KB and ( 10 of ($s*) ) ) and
       		pe.imports("KERNEL32.dll", "Sleep") and
       		pe.imports("KERNEL32.dll", "IsDebuggerPresent")
}
