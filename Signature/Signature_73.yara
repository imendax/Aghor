rule signature_73
{
	meta:
		author = "0xlsd"
		sample = "0347f5e49ebd46d124769565aaf1b24143dc3083270914f7976bc590505f56da"
	
	
	strings:
		$string_1 = {
			20 72 ??
			6E
			20 75 ??
			64 65 72 ??
			57
			69 6E ?? 32 0D 0A 24
			37
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
		}
	
	condition:
		any of them
	
}
