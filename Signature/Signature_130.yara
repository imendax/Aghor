rule signature_130
{
	meta:
		author = "0xlsd"
		sample = "e539c6ec932e00f9eca96eaa3694a7f4c6c9ee73e7c8c06e65a62d2637ce9b66"
	
	
	strings:
		$string_1 = {
			0E
			01 0B
			01 05 ?? ?? ?? ??
			00 00
			96
			00 00
			00 00
			00 00
			08 33
			00 00
			00 10
			00 00
			00 90 ?? ?? ?? ??
			40
			00 00
			10 00
			00 00
		}
	
	condition:
		any of them
	
}
