rule signature_137
{
	meta:
		author = "0xlsd"
		sample = "c353633f9c879ddbe7e38920da36f14554fde9773089c0d7dff13d63e9b95d2f"
	
	
	strings:
		$string_1 = {
			0E
			01 0B
			01 08
			00 00
			B6 01
			00 00
			0E
			00 00
			00 00
			00 00
			A4
			6E
			00 00
			00 40 ??
			00 00
			20 00
			00 00
			00 40 ??
			00 20
			00 00
			00 02
		}
	
	condition:
		any of them
	
}
