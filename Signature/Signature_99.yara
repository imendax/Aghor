rule signature_99
{
	meta:
		author = "0xlsd"
		sample = "9d3841c592e924ef8e690be2f30a0db2fb60b711311ee50352898fe17b35a985"
	
	
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
