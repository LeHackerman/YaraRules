
import "pe"

rule spyeye_strings
{
	meta:
		description = "A Yara rule used to detect SpyEye strings."
		author = "Haroun @LeHackerman"
		reference = "ToBeAdded"
		date = "13/06/2023"
	strings:
		$mutex_main = "__CLEANSWEEP__"  
		$mutex_config_reload = "__CLEANSWEEP_RELOADCFG__"
		$mutex_uninstall = "__CLEANSWEEP_UNINSTALL_"
		$string1 = "KNOCK-COMPLETE"
		$string2 = "KNOCK-ERROR"
		$string3 = "KNOCK"
		$string4 = "LOAD-COMPLETE"
		$string5 = "LOAD-ERROR"
		$string6 = "LOAD"
		$string7 = "COMPLETE"
		$string8 = "data from server is: %s"
		$string9 = "ACTIVE"
		$string10 = "FILL"
		$string11 = "UPDATE_CONFIG"
		$string12 = "UPDATE"
	condition:
		any of ($mutex*) or all of ($string*)
}

rule spyeye_hashing_algorithms
{
	meta:
		description = "A Yara rule used to detect SpyEye's API hashing and string deobfuscation algorithms."
		author = "Haroun @LeHackerman"
		reference = "ToBeAdded"
		date = "13/06/2023"
	strings:
		$api_hashing = { 51 51 83 65 f8 00 8b 45 08 89 45 fc 8b 45 fc 0f be 00 85 c0 74 26 8b 45 f8 c1 e0 07 8b 4d f8 c1 e9 19 0b c1 89 45 f8 8b 45 fc 0f be 00 33 45 f8 89 45 f8 8b 45 fc 40 89 45 fc eb d0 8b 45 f8 c9 c3}

		$string_deobfuscation = { 57 33 ff b8 8c 00 00 00 8b 0c bd 28 50 41 00 3b 4c 24 08 74 05 47 3b f8 72 ee 3b f8 75 04 33 c0 5f c3 53 56 8d 34 bd 68 5e 41 00 8b 06 85 c0 bb b8 50 41 00 74 13 50 8b c7 6b c0 64 03 c3 50 e8 c2 6f 00 00 83  26 00 59 59 8b c7 6b c0 64 5e 03 c3 5b 5f c3 }

	condition:
		any of them
}
