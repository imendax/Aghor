rule signature_69
{
	meta:
		author = "0xlsd"
		sample = "2e59e208adceff2e989e944ff18335138cc91d9020f8b1ec178ac619d7b1c81f"
	
	
	strings:
		$string_1 = {
			20 72 ??
			6E
			20 69 ??
			20 44 4F ??
			20 6D ??
			64 65 2E 0D 0D 0A 24 00
			00 00
			00 00
			00 00
			31 B8 ?? ?? ?? ??
		}
	
	condition:
		any of them
	
}
