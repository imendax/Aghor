rule signature_101
{
	meta:
		author = "0xlsd"
		sample = "f03d64ea80bff57acc50015784361b968fbf41d9010e7e8991bfda84429239d7"
	
	
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
			50
			45
			00 00
			4C
			01 02
			00 00
			00 00
		}
	
	condition:
		any of them
	
}
